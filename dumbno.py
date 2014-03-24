from jsonrpclib import Server
import socket
import time
import select
import json

def parse_entry(line):
    #for now I just need what sequence numbers are used and the age
    parts = line.replace("[","").replace("]","").split()
    seq = int(parts[0])
    if parts[-1] == "ago":
        ago = parts[-2]
        matches = parts[-3]
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
    lines = [l for l in text.splitlines() if 'ip' in l]
    return map(parse_entry, lines)

def make_rules(s, d, proto="ip", sp=None, dp=None):
    a = "host %s" % s 
    ap = sp and "eq %s" % sp or ""

    b = "host %s" % d
    bp = dp and "eq %s" % dp or ""


    rule_a = "%s %s %s %s %s" % (proto, a, ap, b, bp)
    rule_b = "%s %s %s %s %s" % (proto, b, bp, a, ap)

    return rule_a, rule_b

def is_expired(acl):
    if 'any any' in acl['rule']:
        return False
    if 'ago' not in acl:
        return True

    return 'ago' > '0:10:00'

class ACLMgr:
    def __init__(self):
        self.seq = 20
        self.max = 10000
        self.switch = Server( "https://admin:pw@host/command-api" )
        self.remove_expired()

    def refresh(self):
        cmds = [
            "enable",
            "show ip access-lists bulk",
        ]
        response = self.switch.runCmds(version=1, cmds=cmds, format='text')
        acls = response[1]['output']
        acls = parse_acl(acls)
        self.used = set(x["seq"] for x in acls)
        self.rules = set(x["rule"] for x in acls)
        print "Current ACLS"
        for x in acls:
            print "%(seq)r %(rule)r %(matches)r %(ago)r" % x
        return acls

    def calc_next(self):
        wrapped = False
        for x in range(self.seq, self.max) + range(0, self.seq):
            if x not in self.used:
                return x
        raise Exception("Too many ACLS?")

    def add_acl(self, src, dst, proto="ip", sport=None, dport=None):
        rule_a, rule_b = make_rules(src, dst, proto, sport, dport)

        if rule_a in self.rules or rule_b in self.rules:
            return False
        a = self.calc_next()
        b = a + 1

        cmds = [
            "enable",
            "configure",
            "ip access-list bulk",
            "%d deny %s" % (a, rule_a),
            "%d deny %s" % (b, rule_b),
        ]
        print "sending:", "\n".join(cmds)
        response = self.switch.runCmds(version=1, cmds=cmds, format='text')
        self.rules.update([rule_a, rule_b])
        return True

    def remove_acls(self, seqs):
        if not seqs:
            return
        cmds = [
            "enable",
            "configure",
            "ip access-list bulk",
        ]
        for s in seqs:
            cmds.append("no %s" % s)
        print "sending:", "\n".join(cmds)
        response = self.switch.runCmds(version=1, cmds=cmds, format='text')

    def remove_expired(self):
        acls = self.refresh()
        to_remove = [x["seq"] for x in acls if is_expired(x)]
        print "should remove", to_remove
        self.remove_acls(to_remove)
        

class ACLSvr:
    def __init__(self, mgr):
        self.mgr = mgr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', 9000))
        self.last_check = time.time()

    def check(self):
        if time.time() - self.last_check > 60:
            print "Checking..."
            self.mgr.remove_expired()
            self.last_check = time.time()

    def run(self):
        while True:
            readable, _, _ = select.select([self.sock], [], [], 5)
            if readable:
                data, addr = self.sock.recvfrom(1024)
                record = json.loads(data)
                self.mgr.add_acl(**record)
            self.check()
            time.sleep(2)

class ACLClient:
    def __init__(self, host, port=9000):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    def add_acl(self, src, dst, proto="ip", sport=None, dport=None):
        msg = json.dumps(dict(src=src,dst=dst,proto=proto,sport=sport,dport=dport))
        self.sock.sendto(msg, self.addr)

def main():
    mgr = ACLMgr()
    svr = ACLSvr(mgr)
    svr.run()

if __name__ == "__main__":
    main()

