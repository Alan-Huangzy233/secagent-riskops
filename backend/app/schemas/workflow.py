"""Flow / Task / Step / ToolCall / Artifact runtime records.

Mirrors docs/workflow-runtime.md. Every investigation is represented as a
traceable Flow rather than a one-off agent call, so it can be audited and
replayed.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .enums import FlowStatus, RunStatus


class ToolCall(BaseModel):
    tool_call_id: str
    tool_name: str
    input: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] = Field(default_factory=dict)
    status: RunStatus = RunStatus.OK
    error: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    agent_run_ref: str | None = None
    at: str


class Step(BaseModel):
    step_id: str
    name: str
    kind: str  # "deterministic" | "agent" | "policy"
    status: RunStatus = RunStatus.OK
    tool_call_ids: list[str] = Field(default_factory=list)
    at: str


class Task(BaseModel):
    task_id: str
    name: str
    status: RunStatus = RunStatus.OK
    step_ids: list[str] = Field(default_factory=list)


class Artifact(BaseModel):
    artifact_id: str
    kind: str
    ref: str  # id of the produced object
    at: str


class Flow(BaseModel):
    flow_id: str
    flow_type: str
    title: str
    status: FlowStatus = FlowStatus.CREATED
    created_at: str
    updated_at: str
    task_ids: list[str] = Field(default_factory=list)
    artifact_ids: list[str] = Field(default_factory=list)
    related_alert_group_ids: list[str] = Field(default_factory=list)
    related_incident_id: str | None = None
