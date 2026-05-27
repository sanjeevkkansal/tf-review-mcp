from pathlib import Path

from tf_review_mcp.review import review_plan_file

FIXTURE = Path(__file__).parent / "fixtures" / "example_plan.json"


def test_review_counts_actions():
    summary = review_plan_file(FIXTURE)
    assert summary.total_changes == 5
    assert summary.counts.get("replace") == 1
    assert summary.counts.get("create") == 2
    assert summary.counts.get("update") == 2


def test_review_flags_stateful_destroy():
    summary = review_plan_file(FIXTURE)
    addrs = {c.address for c in summary.stateful_destroys}
    assert "aws_db_instance.primary" in addrs


def test_review_flags_high_risk():
    summary = review_plan_file(FIXTURE)
    addrs = {c.address for c in summary.high_risk_changes}
    assert "aws_security_group.web" in addrs
    assert "aws_iam_role.app" in addrs
    assert "aws_s3_bucket.logs" in addrs
    assert "aws_instance.worker" not in addrs


def test_review_notes_present():
    summary = review_plan_file(FIXTURE)
    assert any("stateful" in n.lower() for n in summary.notes)
