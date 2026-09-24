"""Approval binding, the execution gate, verification and automatic rollback."""
from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from app.authorization import make_scope
from app.pipeline import remediation
from app.schemas.enums import AutonomyLevel
from app.tools.harden_ssh import HardenSshExecutor

LAB = Path(__file__).resolve().parents[2] / "examples" / "safety-demo" / "lab"
OPERATOR = "security-operator"


def scope(**overrides):
    fields = dict(autonomy_level=AutonomyLevel.EXECUTE_AFTER_APPROVAL, allowed_actors=(OPERATOR,),
                  target_allowlist=("bastion-01", "web-02"), valid_from="2026-07-01T00:00:00Z",
                  valid_until="2026-12-31T23:59:59Z")
    fields.update(overrides)
    return make_scope(fields.pop("scope_id", "SCOPE-T"), **fields)


@pytest.fixture
def plan(services):
    return remediation.draft_plan(services, "harden_ssh_access", "bastion-01", created_from="INC-1",
                                  evidence_ids=["E1"])


def executor(tmp_path: Path, host: str) -> HardenSshExecutor:
    return HardenSshExecutor(Path(shutil.copytree(LAB / host, tmp_path / host)), host)


def events(services, kind: str) -> list[dict]:
    return [e.payload for e in services.audit.events() if e.event_type == kind]


def test_without_an_approval_nothing_runs(services, plan, tmp_path):
    lab = executor(tmp_path, "bastion-01")
    before = lab.config.read_bytes()
    outcome = remediation.execute_plan(services, plan, scope(), OPERATOR, lab)
    assert outcome.decision.reason_code == "APPROVAL_REQUIRED" and outcome.change is None
    assert lab.config.read_bytes() == before and not events(services, "execution.applied")


def test_an_approval_holds_only_for_the_plan_and_scope_it_was_given(services, plan):
    lab_scope = scope()
    remediation.record_approval(services, plan, lab_scope, OPERATOR)
    assert remediation.valid_approval(services, plan, lab_scope) is not None
    edited = plan.model_copy(update={"parameters": {**plan.parameters, "enforce_key_auth": False}})
    assert remediation.valid_approval(services, edited, lab_scope) is None
    retargeted = plan.model_copy(update={"target": {"asset_id": "web-02"}})
    assert remediation.valid_approval(services, retargeted, lab_scope) is None
    assert remediation.valid_approval(services, plan, scope(scope_version=2)) is None
    decision, _ = remediation.evaluate_execution(services, edited, lab_scope, OPERATOR)
    assert decision.reason_code == "APPROVAL_REQUIRED"


def test_a_later_rejection_withdraws_the_approval(services, plan):
    lab_scope = scope()
    remediation.record_approval(services, plan, lab_scope, OPERATOR)
    remediation.record_approval(services, plan, lab_scope, OPERATOR, decision="rejected")
    assert remediation.valid_approval(services, plan, lab_scope) is None


def test_only_a_permitted_actor_can_record_a_decision(services, plan):
    with pytest.raises(ValueError, match="not a permitted actor"):
        remediation.record_approval(services, plan, scope(), "intruder")
    with pytest.raises(ValueError, match="unknown decision"):
        remediation.record_approval(services, plan, scope(), OPERATOR, decision="maybe")
    assert not services.repo.list("approvals")


def test_an_approved_plan_runs_and_is_verified(services, plan, tmp_path):
    lab_scope = scope()
    approval = remediation.record_approval(services, plan, lab_scope, OPERATOR)
    outcome = remediation.execute_plan(services, plan, lab_scope, OPERATOR, executor(tmp_path, "bastion-01"))
    assert outcome.decision.reason_code == "ALLOW_OK" and outcome.approval == approval
    assert outcome.plan.status.value == "verified" and outcome.rollback is None
    assert outcome.states["before"]["PermitRootLogin"]["value"] == "yes"
    assert outcome.states["after"]["PermitRootLogin"]["value"] == "no"
    [applied] = events(services, "execution.applied")
    assert services.evidence.verify(applied["before_sha256"]) and services.evidence.verify(applied["after_sha256"])
    [verified] = events(services, "execution.verified")
    assert verified["ok"] and services.evidence.verify(verified["report_ref"])


def test_a_failed_verification_rolls_back_without_a_person(services, tmp_path):
    lab_scope = scope()
    plan = remediation.draft_plan(services, "harden_ssh_access", "web-02", created_from="INC-2", evidence_ids=[])
    remediation.record_approval(services, plan, lab_scope, OPERATOR)
    lab = executor(tmp_path, "web-02")
    before = lab.config.read_bytes()
    outcome = remediation.execute_plan(services, plan, lab_scope, OPERATOR, lab)
    assert not outcome.verification.ok and outcome.plan.status.value == "rolled_back"
    assert outcome.rollback["ok"] and lab.config.read_bytes() == before
    assert outcome.states["restored"] == outcome.states["before"]
    [rolled] = events(services, "rollback.applied")
    assert rolled["failed_checks"][0]["setting"] == "PasswordAuthentication"
    assert events(services, "rollback.verified")[0]["ok"]
    assert services.repo.get("action_plans", plan.action_plan_id)["status"] == "rolled_back"


def test_an_executor_for_another_host_is_refused_and_recorded(services, plan, tmp_path):
    lab_scope = scope()
    remediation.record_approval(services, plan, lab_scope, OPERATOR)
    other = executor(tmp_path, "web-02")
    before = other.config.read_bytes()
    outcome = remediation.execute_plan(services, plan, lab_scope, OPERATOR, other)
    assert outcome.refused and outcome.change is None and other.config.read_bytes() == before
    assert "cannot run harden_ssh_access on bastion-01" in events(services, "execution.refused")[0]["reason"]


def test_the_playbook_hardens_only_where_a_password_was_guessed():
    login = {"event_id": "E9", "host": "web-02", "source_had_logged_in_as_account_before": False}
    familiar = {**login, "event_id": "E8", "host": "db-01", "source_had_logged_in_as_account_before": True}
    case = {"successful_logins": [login, familiar]}
    assert remediation.playbook(case, "escalate") == [("harden_ssh_access", "web-02", ["E9"])]
    assert remediation.playbook(case, "dismiss") == [] and remediation.playbook(case, "abstain") == []
    assert remediation.playbook({"successful_logins": []}, "escalate") == []
