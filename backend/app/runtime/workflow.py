"""Workflow runtime: turns each investigation into a traceable Flow.

Every task, step, and tool call is persisted and mirrored into the audit log,
so the whole run can be inspected and replayed. State transitions go through
``set_flow_status`` so they are always recorded (workflow-runtime.md rule 4).
"""
from __future__ import annotations

from typing import Any

from ..core.clock import Clock, isoformat
from ..core.ids import IdFactory
from ..schemas.enums import FlowStatus, RunStatus
from ..schemas.workflow import Artifact, Flow, Step, Task, ToolCall
from ..storage.audit_log import AuditLog
from ..storage.repository import Repository


class WorkflowRuntime:
    def __init__(self, repo: Repository, audit: AuditLog, clock: Clock, ids: IdFactory) -> None:
        self._repo = repo
        self._audit = audit
        self._clock = clock
        self._ids = ids

    def _now(self) -> str:
        return isoformat(self._clock.now())

    def start_flow(self, flow_type: str, title: str) -> Flow:
        now = self._now()
        flow = Flow(
            flow_id=self._ids.next("FLOW"),
            flow_type=flow_type,
            title=title,
            status=FlowStatus.RUNNING,
            created_at=now,
            updated_at=now,
        )
        self._repo.save("flows", flow.flow_id, flow)
        self._audit.record("flow.started", "system", flow_id=flow.flow_id,
                           payload={"flow_type": flow_type, "title": title})
        return flow

    def set_flow_status(self, flow: Flow, status: FlowStatus) -> Flow:
        flow = flow.model_copy(update={"status": status, "updated_at": self._now()})
        self._repo.save("flows", flow.flow_id, flow)
        self._audit.record("flow.status_changed", "system", flow_id=flow.flow_id,
                           payload={"status": status.value})
        return flow

    def add_task(self, flow: Flow, name: str) -> Task:
        task = Task(task_id=self._ids.next("TASK"), name=name)
        self._repo.save("tasks", task.task_id, task)
        flow.task_ids.append(task.task_id)
        self._repo.save("flows", flow.flow_id, flow)
        self._audit.record("task.started", "system", flow_id=flow.flow_id,
                           subject_ref=task.task_id, payload={"name": name})
        return task

    def add_step(self, flow: Flow, task: Task, name: str, kind: str) -> Step:
        step = Step(step_id=self._ids.next("STEP"), name=name, kind=kind, at=self._now())
        self._repo.save("steps", step.step_id, step)
        task.step_ids.append(step.step_id)
        self._repo.save("tasks", task.task_id, task)
        self._audit.record("step.ran", "system", flow_id=flow.flow_id,
                           subject_ref=step.step_id, payload={"name": name, "kind": kind})
        return step

    def tool_call(
        self,
        flow: Flow,
        step: Step,
        tool_name: str,
        input: dict[str, Any],
        output: dict[str, Any],
        *,
        evidence_ids: list[str] | None = None,
        agent_run_ref: str | None = None,
        status: RunStatus = RunStatus.OK,
    ) -> ToolCall:
        call = ToolCall(
            tool_call_id=self._ids.next("TC"),
            tool_name=tool_name,
            input=input,
            output=output,
            status=status,
            evidence_ids=evidence_ids or [],
            agent_run_ref=agent_run_ref,
            at=self._now(),
        )
        self._repo.save("tool_calls", call.tool_call_id, call)
        step.tool_call_ids.append(call.tool_call_id)
        self._repo.save("steps", step.step_id, step)
        self._audit.record("tool.called", agent_run_ref or "system", flow_id=flow.flow_id,
                           subject_ref=call.tool_call_id,
                           payload={"tool": tool_name, "status": status.value})
        return call

    def add_artifact(self, flow: Flow, kind: str, ref: str) -> Artifact:
        artifact = Artifact(artifact_id=self._ids.next("ART"), kind=kind, ref=ref, at=self._now())
        self._repo.save("artifacts", artifact.artifact_id, artifact)
        flow.artifact_ids.append(artifact.artifact_id)
        self._repo.save("flows", flow.flow_id, flow)
        return artifact
