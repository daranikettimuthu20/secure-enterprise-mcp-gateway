"""
RBAC policy engine. Loads policies/roles.yaml and answers:
  - can this role call this tool at all?
  - do the specific arguments satisfy this role's constraints?
  - what should happen if PII is found for this role (block/redact/allow)?

Kept intentionally simple (dict lookups + a couple of constraint checks) so
it's easy to read in a code review. For a production system this is the
natural place to swap in OPA/Rego or Cedar for more expressive policies.
"""
from __future__ import annotations
import yaml
from pathlib import Path
from gateway.models import Role


class PolicyEngine:
    def __init__(self, policy_file: str):
        self._path = Path(policy_file)
        self._policies: dict = {}
        self.reload()

    def reload(self) -> None:
        with open(self._path, "r") as f:
            data = yaml.safe_load(f)
        self._policies = data.get("roles", {})

    def _role_policy(self, role: Role) -> dict:
        return self._policies.get(role.value, {})

    def can_call(self, role: Role, tool_name: str) -> tuple[bool, str | None]:
        policy = self._role_policy(role)
        tools = policy.get("tools", [])
        if "*" in tools or tool_name in tools:
            return True, None
        return False, f"Role '{role.value}' is not authorized to call tool '{tool_name}'"

    def check_constraints(self, role: Role, tool_name: str, arguments: dict) -> tuple[bool, str | None]:
        policy = self._role_policy(role)
        constraints = policy.get("constraints", {}).get(tool_name, {})
        if not constraints:
            return True, None

        if "path_prefix" in constraints and "path" in arguments:
            prefix = constraints["path_prefix"]
            if not str(arguments["path"]).startswith(prefix):
                return False, (
                    f"Argument 'path'={arguments['path']!r} violates path_prefix "
                    f"constraint {prefix!r} for role '{role.value}'"
                )

        if "domain_allowlist" in constraints and "to" in arguments:
            to_addr = str(arguments["to"])
            domain = to_addr.split("@")[-1].lower()
            allowed = [d.lower() for d in constraints["domain_allowlist"]]
            if domain not in allowed:
                return False, (
                    f"Recipient domain '{domain}' not in allowlist {allowed} "
                    f"for role '{role.value}'"
                )

        return True, None

    def pii_action(self, role: Role) -> str:
        return self._role_policy(role).get("pii_action", "block")

    def authorize(self, role: Role, tool_name: str, arguments: dict) -> tuple[bool, str | None]:
        ok, reason = self.can_call(role, tool_name)
        if not ok:
            return False, reason
        ok, reason = self.check_constraints(role, tool_name, arguments)
        if not ok:
            return False, reason
        return True, None
