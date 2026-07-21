from __future__ import annotations

from app.schemas.enums import FlowStatus


def test_runtime_records_flow_task_step_toolcall(services):
    rt = services.runtime
    flow = rt.start_flow("soc_investigation", "test flow")
    task = rt.add_task(flow, "task one")
    step = rt.add_step(flow, task, "step one", "deterministic")
    call = rt.tool_call(flow, step, "some.tool", input={"a": 1}, output={"b": 2})

    assert services.repo.get("flows", flow.flow_id)["status"] == FlowStatus.RUNNING
    assert task.task_id in services.repo.get("flows", flow.flow_id)["task_ids"]
    assert step.step_id in services.repo.get("tasks", task.task_id)["step_ids"]
    assert call.tool_call_id in services.repo.get("steps", step.step_id)["tool_call_ids"]


def test_audit_chain_is_intact_and_tamper_evident(services):
    rt = services.runtime
    flow = rt.start_flow("soc_investigation", "test flow")
    rt.add_task(flow, "t")
    assert services.audit.verify_chain() is True

    # Tamper with a recorded event: the hash chain must detect it.
    events = services.audit._events  # noqa: SLF001 - deliberate white-box test
    forged = events[0].model_copy(update={"actor": "attacker"})
    events[0] = forged
    assert services.audit.verify_chain() is False
