"""Agent integration boundary.

Product modules never import a model SDK. They request a capability from the
registry and receive something that satisfies ``AgentContract``. A real
deployment plugs a model-backed agent in behind this same seam via a
``ModelProvider``; the walking skeleton ships a deterministic agent so the
pipeline is reproducible and testable without a provider.

An agent *proposes*. It cannot authorize, approve, or invoke an executor — that
is the policy engine's job (see backend/app/policy/engine.py).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class AgentResult:
    output: dict[str, Any]
    confidence: float
    evidence_ids: list[str] = field(default_factory=list)
    rationale: str = ""


class ModelProvider(Protocol):
    """Vendor-neutral inference seam (unused by the deterministic agent)."""

    def infer(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]: ...


class AgentContract(ABC):
    name: str
    version: str

    @abstractmethod
    def run(self, context: dict[str, Any]) -> AgentResult: ...


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, AgentContract] = {}

    def register(self, agent: AgentContract) -> None:
        self._agents[agent.name] = agent

    def resolve(self, name: str, version: str | None = None) -> AgentContract:
        agent = self._agents.get(name)
        if agent is None:
            raise KeyError(f"No agent registered for capability {name!r}")
        if version is not None and agent.version != version:
            raise KeyError(f"Agent {name!r} version {agent.version} != requested {version}")
        return agent
