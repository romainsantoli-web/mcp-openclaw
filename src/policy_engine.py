from __future__ import annotations

from dataclasses import dataclass


class PolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyEngine:
    def __init__(
        self,
        secure_production_mode: bool,
        blocked_tools: tuple[str, ...],
        allow_write_tools: bool,
        allow_network_tools: bool,
    ) -> None:
        self._secure_production_mode = secure_production_mode
        self._blocked_tools = set(blocked_tools)
        self._allow_write_tools = allow_write_tools
        self._allow_network_tools = allow_network_tools

    def check(self, tool_name: str, category: str = "read") -> PolicyDecision:
        if tool_name in self._blocked_tools:
            return PolicyDecision(allowed=False, reason="blocked_by_tool_policy")

        if not self._secure_production_mode:
            return PolicyDecision(allowed=True, reason="allowed_non_secure_mode")

        if category == "write" and not self._allow_write_tools:
            return PolicyDecision(allowed=False, reason="write_tools_disabled")

        if category == "network" and not self._allow_network_tools:
            return PolicyDecision(allowed=False, reason="network_tools_disabled")

        return PolicyDecision(allowed=True, reason="allowed_by_secure_policy")

    def guard(self, tool_name: str, category: str = "read") -> None:
        decision = self.check(tool_name=tool_name, category=category)
        if not decision.allowed:
            raise PolicyError(
                f"Action refusée pour {tool_name} ({category}): {decision.reason}"
            )

    def diagnostics(self) -> dict[str, object]:
        return {
            "secure_production_mode": self._secure_production_mode,
            "blocked_tools": sorted(self._blocked_tools),
            "allow_write_tools": self._allow_write_tools,
            "allow_network_tools": self._allow_network_tools,
        }
