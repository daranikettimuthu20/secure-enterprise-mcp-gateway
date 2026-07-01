import os
from gateway.security.policy_engine import PolicyEngine
from gateway.models import Role

POLICY_FILE = os.path.join(os.path.dirname(__file__), "..", "policies", "roles.yaml")


def _engine():
    return PolicyEngine(POLICY_FILE)


def test_admin_can_call_anything():
    engine = _engine()
    ok, _ = engine.can_call(Role.ADMIN, "send_email")
    assert ok is True


def test_readonly_agent_cannot_send_email():
    engine = _engine()
    ok, reason = engine.can_call(Role.READONLY_AGENT, "send_email")
    assert ok is False
    assert "not authorized" in reason


def test_analyst_read_file_path_constraint():
    engine = _engine()
    ok, _ = engine.check_constraints(Role.ANALYST, "read_file", {"path": "/data/shared/report.txt"})
    assert ok is True
    ok, reason = engine.check_constraints(Role.ANALYST, "read_file", {"path": "/data/private/secrets.txt"})
    assert ok is False
    assert "path_prefix" in reason


def test_support_bot_email_domain_allowlist():
    engine = _engine()
    ok, _ = engine.check_constraints(Role.SUPPORT_BOT, "send_email", {"to": "user@mycompany.com"})
    assert ok is True
    ok, reason = engine.check_constraints(Role.SUPPORT_BOT, "send_email", {"to": "user@evil.com"})
    assert ok is False
    assert "allowlist" in reason


def test_full_authorize_combines_both_checks():
    engine = _engine()
    ok, _ = engine.authorize(Role.ANALYST, "read_file", {"path": "/data/shared/x.txt"})
    assert ok is True
    ok, reason = engine.authorize(Role.ANALYST, "send_email", {"to": "a@b.com"})
    assert ok is False  # analyst has no send_email tool at all
