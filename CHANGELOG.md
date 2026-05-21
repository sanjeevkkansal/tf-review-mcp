# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-05-21

### Added
- GCP coverage in `HIGH_RISK_TYPES`: `google_compute_firewall`,
  `google_container_node_pool`, `google_dns_managed_zone`,
  `google_dns_record_set`, `google_project_iam_binding`.
- `google_compute_instance` added to `STATEFUL_TYPES` so a replace
  (boot disk + local SSD loss) surfaces as a blocker.
- Diff-aware public-exposure check: `google_compute_firewall` changes
  that add `0.0.0.0/0` or `::/0` to `source_ranges` are flagged as
  `public_exposure_changes` and reported as blockers.
- New `ExposureChange` dataclass and `public_exposure_changes` field on
  `ReviewSummary`.
- GCP test fixture (`tests/fixtures/gcp_plan.json`) and five new tests
  covering firewall widening, GCE instance replace, GCP high-risk types,
  child-resource scoping, and the new note text.

### Changed
- `suggest_review_comments` now emits a `blocker` for each public-exposure
  finding and dedups by resource address so a single resource never gets
  multiple comments.
- README and DESIGN updated to describe the new diff-aware capability
  and the broader provider coverage.

## [0.1.0] - 2026-05-20

### Added
- Initial release.
- `review_plan` and `suggest_review_comments` MCP tools.
- AWS / GCP / Azure high-risk type list (conservative defaults).
- Stateful-destroy detection for RDS, DynamoDB, S3, ElastiCache, Cloud SQL,
  GCS, Azure SQL.
- Fixture-backed unit tests.
- Stdio transport via FastMCP; `tf-review-mcp` console entry point.
