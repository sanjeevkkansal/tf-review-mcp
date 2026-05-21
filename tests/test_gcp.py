from pathlib import Path

from tf_review_mcp.review import review_plan_file

FIXTURE = Path(__file__).parent / "fixtures" / "gcp_plan.json"


def test_firewall_widening_flagged_as_public_exposure():
    summary = review_plan_file(FIXTURE)
    addrs = {e.address for e in summary.public_exposure_changes}
    assert "google_compute_firewall.rpc_public" in addrs
    finding = next(e for e in summary.public_exposure_changes
                   if e.address == "google_compute_firewall.rpc_public").finding
    assert "0.0.0.0/0" in finding


def test_compute_instance_replace_is_stateful_destroy():
    summary = review_plan_file(FIXTURE)
    addrs = {c.address for c in summary.stateful_destroys}
    assert "google_compute_instance.op_geth" in addrs
    assert "google_sql_database_instance.indexer" in addrs


def test_gcp_high_risk_types_recognized():
    summary = review_plan_file(FIXTURE)
    addrs = {c.address for c in summary.high_risk_changes}
    assert "google_dns_record_set.api" in addrs
    assert "google_project_iam_member.deployer" in addrs
    assert "google_compute_firewall.rpc_public" in addrs


def test_non_high_risk_gcp_resources_not_flagged():
    summary = review_plan_file(FIXTURE)
    addrs = {c.address for c in summary.high_risk_changes}
    # google_storage_bucket_object is not the same as google_storage_bucket
    assert "google_storage_bucket_object.config" not in addrs


def test_notes_mention_public_exposure():
    summary = review_plan_file(FIXTURE)
    assert any("public exposure" in n.lower() for n in summary.notes)
    assert any("stateful" in n.lower() for n in summary.notes)
