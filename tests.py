from nose.tools import eq_

from dumbno import make_rule, ip_family

def _make_rule_test_case(output, kwargs):
    eq_(output, make_rule(**kwargs))

def test_make_rule():
    cases = [
        ('ip host 1.2.3.4 any',
            dict(s="1.2.3.4")),
        ('ip host 1.2.3.4 host 5.6.7.8',
            dict(s="1.2.3.4", d="5.6.7.8")),
        ('tcp host 1.2.3.4 eq 123 host 5.6.7.8 eq 567',
            dict(s="1.2.3.4", d="5.6.7.8", sp=123, dp=567, proto='tcp')),
        ('tcp host 1.2.3.4 any host 5.6.7.8 eq 567',
            dict(s="1.2.3.4", d="5.6.7.8", dp=567, proto='tcp')),
        ('tcp any host 5.6.7.8 eq 567',
            dict(d="5.6.7.8", dp=567, proto='tcp')),
        ('ip any host 5.6.7.8',
            dict(d="5.6.7.8")),
        ('tcp any any eq 567',
            dict(dp='567', proto='tcp')),
    ]
    for expected, kwargs in cases:
        yield _make_rule_test_case, expected, kwargs

def _ip_family_test_case(ip, expected):
    eq_(expected, ip_family(ip))

def testip_family():
    cases = [
        ("1.2.3.4", "ip"),
        ("2601:a6:2000:3712:8a2:ce2e:25db:2aa1", "ipv6"),
        ("1.2.3.4.5", None),
        ("foo", None),
    ]
    for ip, expected in cases:
        yield _ip_family_test_case, ip, expected
