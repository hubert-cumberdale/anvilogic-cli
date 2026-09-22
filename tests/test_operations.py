from __future__ import annotations

import pytest

from anvilogic_cli.operations import OperationCatalog, OperationCatalogError


def test_bundled_operation_registry_is_distilled_and_complete() -> None:
    catalog = OperationCatalog.bundled()
    stats = catalog.stats()

    assert stats["operations"] == 74
    assert stats["methods"] == {"GET": 51, "POST": 23}
    assert stats["risks"] == {"bulk": 2, "read": 51, "write": 21}
    assert stats["confidence"] == {"confirmed": 74}
    assert stats["evidence_classes"] == {"distilled-private-traffic": 74}
    assert stats["source"]["evidence_provenance"] == "private traffic"
    assert stats["source"]["private_evidence_retained"] is False
    assert not any("extauthconfig" in name for name in catalog.names())


def test_every_operation_has_review_metadata_and_no_model_claims() -> None:
    for operation in OperationCatalog.bundled().matching():
        assert operation.risk in {"read", "write", "bulk", "destructive"}
        assert operation.confidence in {"confirmed", "inferred", "unknown"}
        assert operation.evidence_class == "distilled-private-traffic"
        assert operation.last_verified == "2026-09-22"
        assert "model" not in operation.as_dict()


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
        "version": 2,
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
