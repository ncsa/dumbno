from jsonrpclib import Server
import socket
import time
import json
import sys
import logging


def parse_entry(line):
    #for now I just need what sequence numbers are used and the age
    parts = line.replace("[","").replace("]","").split()
    seq = int(parts[0])
    if parts[-1] == "ago":
        ago = parts[-2]
        matches = parts[-3].strip(",")
        rule = ' '.join(parts[2:-4])
    else:
        ago = matches = None
        rule = ' '.join(parts[2:])

    return {
        "seq": seq,
        "rule": rule,
        "ago": ago,
        "matches": matches,
    }

def parse_acl(text):
    lines = [l for l in text.splitlines() if 'host' in l]
    return map(parse_entry, lines)

def make_rule(s, d, proto="ip", sp=None, dp=None):
    a = "host %s" % s 
    ap = sp and "eq %s" % sp or ""

    b = "host %s" % d
    bp = dp and "eq %s" % dp or ""

    return "%s %s %s %s %s" % (proto, a, ap, b, bp)

class ACLMgr:
    def __init__(self, ports, logger):
        self.acls = dict(("bulk_%s" % port, []) for port in ports)
        self.ports = ports
        self.logger = logger

        self.min = 500
        self.max = 100000
        self.seq = self.min + 1
        self.switch = Server( "https://admin:pw@host/command-api" )

        self.setup()
        self.remove_expired()


    def acl_exists(self, acl):
        cmds = [
            "enable",
            "show ip access-lists %s" % acl,
        ]
        response = self.switch.runCmds(version=1, cmds=cmds, format='text')
        acls = response[1]['output']
        return bool(acls.strip())

    def setup_acl(self, port):
        acl = "bulk_%s" % port
        if self.acl_exists(acl):
            return True

        self.logger.info("Setting up ACL for port %s", port)
        cmds = [
            "enable",
            "configure",
            "ip access-list %s" % acl,
            "statistics per-entry",
            "10 permit tcp any any fin",
            "20 permit tcp any any syn",
            "30 permit tcp any any rst",
            "100001 permit ip any any",
            "interface %s" % port,
            "ip access-group %s in" % acl,
        ]
        response = self.switch.runCmds(version=1, cmds=cmds, format='text')

    def setup(self):
        for port in self.ports:
            self.setup_acl(port)

    def refresh(self):
        cmds = [
            "enable",
        ]
        for acl in self.acls:
            cmds.append("show ip access-lists %s" % acl)
        response = self.switch.runCmds(version=1, cmds=cmds, format='text')
        
        self.all_seqs = set()
        self.all_rules = set()
        self.total_acls = 0
        for acl, result in zip(self.acls, response[1:]):
            acls = parse_acl(result['output'])
            self.acls[acl] = acls

            seqs  = set(x["seq"] for x in acls)
            rules = set(x["rule"] for x in acls)

            self.all_seqs.update(seqs)
            self.all_rules.update(rules)

            self.total_acls += len(acls)

        return self.acls

    def dump(self, acls, op="CURRENT"):
        if not acls:
            return
        for x in acls:
            x["op"] = op
            self.logger.info('op=%(op)s seq=%(seq)s rule="%(rule)s" matches=%(matches)s ago=%(ago)s' % x)

    def calc_next(self):
        for x in range(self.seq, self.max) + range(self.min, self.seq):
            if x % 2 == 0: continue #i want an odd number
            if x not in self.all_seqs:
                return x
        raise Exception("Too many ACLS?")

    def add_acl(self, src, dst, proto="ip", sport=None, dport=None):
        rule = make_rule(src, dst, proto, sport, dport)

        if rule in self.all_rules:
            return False

        cmds = [
            "enable",
            "configure",
        ]
        self.seq = self.calc_next()
        for acl in self.acls:
            cmds.extend([
                "ip access-list %s" % acl,
                "%d deny %s" % (self.seq, rule),
            ])
        self.logger.info("op=ADD seq=%s rule=%r" % (self.seq, rule))
        response = self.switch.runCmds(version=1, cmds=cmds, format='text')
        self.all_rules.add(rule)
        self.all_seqs.add(self.seq)
        return True

    def remove_acls(self, to_remove):
        cmds = [
            "enable",
            "configure",
        ]
        for acl, entries in to_remove.items():
            cmds.append("ip access-list %s" % acl)
            for r in entries:
                cmds.append("no %s" % r['seq'])
        self.logger.debug("Sending:" + "\n".join(cmds))
        response = self.switch.runCmds(version=1, cmds=cmds, format='text')

    def is_expired(self, acl):
        if acl['seq'] <= self.min or acl['seq'] >= self.max:
            return False
        if 'any any' in acl['rule']:
            return False
        if acl['ago'] is None:
            return True

        return acl['ago'] > '0:01:00'


    def remove_expired(self):
        acls = self.refresh()

        to_remove = {}
        to_remove_flat = []
        for acl, entries in acls.items():
            removable = filter(self.is_expired, entries)
            to_remove[acl] = removable
            to_remove_flat.extend(removable)

        self.dump(to_remove_flat, op="REMOVE")

        if to_remove_flat:
            self.remove_acls(to_remove)
            acls = self.refresh()
            self.logger.info("total_acls=%d", self.total_acls)
            #self.dump(acls)
        

class ACLSvr:
    def __init__(self, mgr):
        self.mgr = mgr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', 9000))
        self.sock.settimeout(5)
        self.last_check = 0

    def check(self):
        if time.time() - self.last_check > 30:
            self.mgr.remove_expired()
            self.last_check = time.time()

    def run(self):
        while True:
            self.check()
            sys.stdout.flush()

            try :
                data, addr = self.sock.recvfrom(1024)
            except socket.timeout:
                continue

            record = json.loads(data)
            if '129.21.16' in record['src'] or '129.21.16' in record['dst']: #no idea what is up with this host
                record['sport'] = record['dport'] = None
            self.mgr.add_acl(**record)
            self.sock.sendto("ok", addr)

class ACLClient:
    def __init__(self, host, port=9000):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1)
    
    def add_acl(self, src, dst, proto="ip", sport=None, dport=None):
        msg = json.dumps(dict(src=src,dst=dst,proto=proto,sport=sport,dport=dport))
        self.sock.sendto(msg, self.addr)
        try :
            data, addr = self.sock.recvfrom(1024)
            return data
        except socket.timeout:
            return None

def main():
    PORTS = ["Et1", "Et2", "Et3", "Et4", "Et5", "Et6", "Et7", "Et8"]

    format = '%(asctime)-15s %(levelname)s %(message)s'
    logging.basicConfig(level=logging.INFO, format=format)
    logger = logging.getLogger("dumbno")
    logger.info("Started")
    mgr = ACLMgr(PORTS, logger)
    svr = ACLSvr(mgr)
    svr.run()

if __name__ == "__main__":
    main()

