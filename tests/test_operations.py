from __future__ import annotations

import hashlib
import json
from importlib import resources

import pytest

from anvilogic_cli.operations import OperationCatalog, OperationCatalogError


def test_bundled_operation_registry_is_distilled_and_complete() -> None:
    catalog = OperationCatalog.bundled()
    stats = catalog.stats()

    assert stats["operations"] == 344
    assert stats["methods"] == {
        "DELETE": 18,
        "GET": 155,
        "PATCH": 17,
        "POST": 144,
        "PUT": 10,
    }
    assert stats["risks"] == {
        "bulk": 2,
        "destructive": 18,
        "read": 155,
        "write": 169,
    }
    assert stats["confidence"] == {"confirmed": 27, "publicly-documented": 317}
    assert stats["evidence"] == {
        "distilled-private-traffic": 74,
        "public-openapi": 317,
    }
    assert stats["request_body_required"] == {
        "false": 238,
        "true": 94,
        "unknown": 12,
    }
    assert stats["source"]["private_evidence_provenance"] == "distilled private traffic"
    assert stats["source"]["private_evidence_retained"] is False
    assert stats["source"]["public_openapi"] == {
        "retrieved": "2026-09-22",
        "sha256": "0e96b604ed12ef29007b38f209855f9a5577ae198ee330fa06692ddf876f884c",
        "title": "Search API Manual Documentation",
        "url": (
            "https://openapi.gitbook.com/o/j9GRuNhp1hds6GRILKW4/spec/"
            "anvilogic-combined-apis.yaml"
        ),
        "version": "8.1.0.0",
    }
    assert not any("extauthconfig" in name for name in catalog.names())


def test_all_public_operation_facts_match_the_reviewed_projection() -> None:
    payload = json.loads(
        resources.files("anvilogic_cli").joinpath("operations.json").read_text()
    )
    public = [
        item for item in payload["operations"] if "public-openapi" in item["evidence"]
    ]
    projection = json.dumps(public, sort_keys=True, separators=(",", ":")).encode()

    assert len(public) == 317
    assert hashlib.sha256(projection).hexdigest() == (
        "dbf52202fe4e9918b7e98521080f8db0dabc3e298ee4084dc525f6a8f05f1e4d"
    )


def test_v4_preserves_every_legacy_operation_id() -> None:
    operation_ids = OperationCatalog.bundled().names()
    projection = json.dumps(operation_ids, separators=(",", ":")).encode()

    assert hashlib.sha256(projection).hexdigest() == (
        "4808bf16ea9d07c8f9f4b6bccc036247828cecc346ed0f611ef44ce7705e76c4"
    )


def test_every_operation_has_review_metadata_and_no_model_claims() -> None:
    for operation in OperationCatalog.bundled().matching():
        assert operation.risk in {"read", "write", "bulk", "destructive"}
        assert operation.confidence in {"confirmed", "publicly-documented"}
        assert operation.evidence
        assert set(operation.evidence) <= {
            "distilled-private-traffic",
            "public-openapi",
        }
        assert operation.last_verified == "2026-09-22"
        assert operation.request_body_required in {True, False, None}
        assert "model" not in operation.as_dict()


def test_public_and_private_evidence_are_distinguished() -> None:
    operations = OperationCatalog.bundled().matching()
    public = [item for item in operations if "public-openapi" in item.evidence]
    overlap = [item for item in public if "distilled-private-traffic" in item.evidence]
    private_only = [item for item in operations if item.evidence == ("distilled-private-traffic",)]

    assert len(public) == 317
    assert len(overlap) == 47
    assert len(private_only) == 27
    assert {item.operation_id for item in private_only} == {
        "get.api.notification.list",
        "get.api.org.relations",
        "get.api.task.inventory",
        "get.pipelines.jobs",
        "get.pipelines.supported",
        "get.services.ai.copilot.tools",
        "get.services.ai.search-agent.tools",
        "get.services.case.metadata",
        "get.services.feature-flag",
        "get.services.monteai.copilot-license",
        "get.services.msp.orgs.allowlist",
        "get.services.msp.orgs.triage",
        "get.strix.connector.list",
        "get.strix.connector.mcp-custom",
        "get.waygate.connected",
        "post.api.cloudapp.get-users",
        "post.services.case.aggregate.by-age",
        "post.services.case.aggregate.by-category",
        "post.services.case.aggregate.by-priority",
        "post.services.case.aggregate.by-status",
        "post.services.case.search",
        "post.services.triage.alert.aggregate.by-severity",
        "post.services.triage.alert.aggregate.by-status",
        "post.services.triage.alert.aggregate.topn-coi-fields",
        "post.services.triage.alert.summary-count",
        "post.strix.blueprint.search",
        "post.strix.session.search",
    }


def test_public_openapi_expands_reviewed_query_allowlists() -> None:
    catalog = OperationCatalog.bundled()
    expected = {
        "get.api.analytic.rule-version": ["hash", "ruleid", "skipSaved", "type"],
        "get.api.analytic.rule-versions": ["limit", "ruleid", "type"],
        "get.api.analytic.use-case-counts": ["taskOnly"],
        "get.api.collab.comments": ["id", "limit", "objType", "offset", "ruleid", "since"],
        "get.api.info.user": ["detailed"],
        "get.api.org.list-siem-configs": ["type"],
        "get.api.priorities.get": ["type"],
        "get.api.proposal.list": ["recommendationType"],
        "get.services.allowlist.rule": ["limit", "offset", "orgs"],
        "get.services.triage.alert.status": [
            "common_only",
            "for_suppression_annotation",
            "orgs",
        ],
        "post.services.triage.alert.search": ["mode", "orgs"],
    }

    assert {
        operation_id: list(catalog.get(operation_id).query_params)
        for operation_id in expected
    } == expected


def test_operation_lookup_is_case_insensitive() -> None:
    operation = OperationCatalog.bundled().get("GET.API.INFO.USER")

    assert operation.path == "/api/info/user"
    assert operation.risk == "read"
    assert operation.request_body is False


def test_path_parameters_are_required_and_encoded_as_one_segment() -> None:
    operation = OperationCatalog.bundled().get("get.services.platform.setting")

    assert operation.render_path([("setting_name", "one/two")]).endswith("/one%2Ftwo")
    with pytest.raises(ValueError, match="Missing path parameter"):
        operation.render_path([])


def test_unobserved_query_parameter_is_rejected() -> None:
    operation = OperationCatalog.bundled().get("get.api.info.user")

    with pytest.raises(ValueError, match="Unreviewed query parameter"):
        operation.validate_query([("tenant", "example")])


def test_unknown_operation_is_rejected() -> None:
    with pytest.raises(OperationCatalogError, match="Unknown reviewed operation"):
        OperationCatalog.bundled().get("delete.everything")


def test_registry_rejects_missing_review_metadata() -> None:
    operation = OperationCatalog.bundled().get("get.api.info.user").as_dict()
    operation.pop("requires_apply")
    operation.pop("path_params")
    operation.pop("confidence")
    payload = {
        "version": 4,
        "source": OperationCatalog.bundled().source,
        "operations": [operation],
    }

    with pytest.raises(OperationCatalogError, match="metadata fields"):
        OperationCatalog.from_dict(payload)


def test_exporter_operations_resolve_from_registry() -> None:
    catalog = OperationCatalog.bundled()

    assert catalog.get("post.api.search.scenario-list-view").risk == "bulk"
    assert catalog.get("get.api.analytic.use-case").risk == "read"
    assert catalog.get("post.api.search.scenario-group-query").risk == "bulk"


def test_new_parameter_ids_and_mutation_apply_gates_are_deterministic() -> None:
    catalog = OperationCatalog.bundled()
    operation = catalog.get("delete.services.org.by-org-id.insights.health.by-id")

    assert operation.path_params == ("org_id", "id")
    assert operation.risk == "destructive"
    assert operation.requires_apply is True
    assert all(
        item.requires_apply
        for item in catalog.matching()
        if item.method in {"DELETE", "PATCH", "POST", "PUT"}
    )
