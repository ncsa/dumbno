from jsonrpclib import Server

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
        self.acls = self.refresh()

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
            print x
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
        response = self.switch.runCmds(version=1, cmds=cmds, format='text')
        self.rules.update([rule_a, rule_b])
        return True

    def remove_acls(self, seqs):
        cmds = [
            "enable",
            "configure",
            "ip access-list bulk",
        ]
        for s in seqs:
            cmds.append("no %s" % s)
        response = self.switch.runCmds(version=1, cmds=cmds, format='text')

        self.acls = self.refresh()

    def remove_expired(self):
        acls = self.refresh()
        to_remove = [x["seq"] for x in self.acls if is_expired(x)]
        print "should remove", to_remove
        self.remove_acls(to_remove)
        

def main():
    mgr = ACLMgr()
    #print mgr.add_acl("33.33.33.33", "44.44.44.46", "tcp", 14531, 80)
    mgr.remove_expired()

if __name__ == "__main__":
    main()

