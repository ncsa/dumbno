from jsonrpclib import Server
import time

INT = 5
ingress = ["Ethernet%d" % x for x in (1,2,3,4,5,6,7,8)]
egress  = ["Ethernet%d" % x for x in (33,34,35,36)]
 
def get_stats(switch):
    response = switch.runCmds(version=1, cmds=["show interfaces counters"], format='json')[0]
    ifs = response['interfaces']

    ibytes = sum(ifs[x]['inOctets'] for x in ingress)
    ebytes = sum(ifs[x]['outOctets'] for x in egress)
    return ibytes, ebytes

def main():
    switch = Server( "https://admin:pw@sw/command-api" )
    l_ibytes, l_ebytes = get_stats(switch)
    while True:
        time.sleep(INT)
        ibytes, ebytes = get_stats(switch)

        ibw = (ibytes - l_ibytes) *8 / INT / 1024 / 1024
        ebw = (ebytes - l_ebytes) *8 / INT / 1024 / 1024

        print "mbps: in=%d out=%d saved=%d" %(ibw, ebw, ibw-ebw)

        l_ibytes, l_ebytes = ibytes, ebytes

if __name__ == "__main__":
    main()

