from nose.tools import eq_

from dumbno import make_rule

def _make_rule_test_case(output, kwargs):
    eq_(output, make_rule(**kwargs))

def test_make_rule():
    cases = [
        ('ip host 1.2.3.4 any',
            dict(s="1.2.3.4")),
        ('ip host 1.2.3.4 host 5.6.7.8',
            dict(s="1.2.3.4", d="5.6.7.8")),
        ('ip host 1.2.3.4 eq 123 host 5.6.7.8 eq 567',
            dict(s="1.2.3.4", d="5.6.7.8", sp=123, dp=567)),
    ]
    for expected, kwargs in cases:
        yield _make_rule_test_case, expected, kwargs
