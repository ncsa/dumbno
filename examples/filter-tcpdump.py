#!/usr/bin/env python
""" Filter a flow using dumbno based on tcpdump formatting

./filter-tcpdump.py '1.2.3.4.80 -> 5.6.7.8.45231'
"""

import sys

from dumbno import ACLClient
def extract(conn):
    f, _, t = conn.split()

    src, sport = f.rsplit(".", 1)
    dst, dport = t.rsplit(".", 1)

    return src,dst, 'tcp', sport, dport

def main():
    conn = extract(sys.argv[1])
    print conn
    c=ACLClient('localhost')
    for x in range(1,11):
        if c.add_acl(*conn):
            print "ok, attempt:", x
            return 0
    print "fail"
    return 1

if __name__ == "__main__":
    sys.exit(main())
