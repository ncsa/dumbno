No elephant flows!

Usage
=====

Copy examples/example\_dumbno.cfg and edit to match your environment.

Start:

    ./dumbno.py dumbno.cfg


Shunting a flow
===============

    >>> import dumbno
    >>> d = dumbno.ACLClient('localhost')
    >>> d.add_acl(src="192.168.1.1", dst="192.168.1.2")
    'ok'
    >>> d.add_acl(src="192.168.1.1", dst="192.168.1.2", proto='tcp', sport='123', dport='456')
    'ok'

The log will show the rule being added, and after a minute or so you will see
the per-port rules get auto purged from all access groups:

    2014-04-28 11:21:11,539 INFO op=ADD seq=501 rule=u'ip host 192.168.1.1  host 192.168.1.2 '

    2014-04-28 11:21:32,982 INFO op=REMOVE acl=bulk_8 seq=501 rule="ip host 192.168.1.1 host 192.168.1.2" matches=None ago=None
    2014-04-28 11:21:32,982 INFO op=REMOVE acl=bulk_7 seq=501 rule="ip host 192.168.1.1 host 192.168.1.2" matches=None ago=None
    2014-04-28 11:21:32,983 INFO op=REMOVE acl=bulk_6 seq=501 rule="ip host 192.168.1.1 host 192.168.1.2" matches=None ago=None
    2014-04-28 11:21:32,983 INFO op=REMOVE acl=bulk_5 seq=501 rule="ip host 192.168.1.1 host 192.168.1.2" matches=None ago=None
    2014-04-28 11:21:32,983 INFO op=REMOVE acl=bulk_4 seq=501 rule="ip host 192.168.1.1 host 192.168.1.2" matches=None ago=None
    2014-04-28 11:21:32,983 INFO op=REMOVE acl=bulk_3 seq=501 rule="ip host 192.168.1.1 host 192.168.1.2" matches=None ago=None
    2014-04-28 11:21:32,983 INFO op=REMOVE acl=bulk_2 seq=501 rule="ip host 192.168.1.1 host 192.168.1.2" matches=None ago=None

A rule that had activity will look like this:

    2014-04-28 11:21:32,983 INFO op=REMOVE acl=bulk_2 seq=729 rule="tcp host 192.168.1.2 eq 39329 host 192.168.1.1 eq 39032" matches=359 ago=0:01:22


About Configuring Port mapping
===============================

Using a single ACL shared by all ingress ports limits the total number of
entries you can have.  If you have a lot of ingress ports map them to
distinct ACLS which will distribute the entries across TCAM.
