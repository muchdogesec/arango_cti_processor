from types import SimpleNamespace
from unittest.mock import patch
import pytest
import sys
from datetime import UTC, date, datetime
from arango_cti_processor.__main__ import (
    parse_arguments,
    main,
    run_all,
    RELATION_MANAGERS,
)  # adjust the import if needed


def test_main():
    with (
        patch(
            "arango_cti_processor.__main__.parse_arguments",
            return_value=SimpleNamespace(dead=2, not_dead=1),
        ) as mock_parse,
        patch("arango_cti_processor.__main__.run_all") as mock_run,
    ):
        main()
        mock_parse.assert_called_once()
        mock_run.assert_called_once_with(dead=2, not_dead=1)


def test_run_all(session_processor, monkeypatch):
    with patch(
        "arango_cti_processor.__main__.import_default_objects"
    ) as mock_import_defaults:
        processed_modes = []
        for v in RELATION_MANAGERS.values():
            monkeypatch.setattr(
                v,
                "process",
                lambda self, *args, **kw: processed_modes.append(
                    self.relationship_note
                ),
            )
        run_all(
            session_processor.db.name,
            modes=["capec-attack", "cwe-capec"],
        )
        print(mock_import_defaults.call_args[1])
        assert mock_import_defaults.call_args[1] == dict(
            default_objects=[],
            collections=[
                "mitre_capec_edge_collection",
                "mitre_capec_vertex_collection",
                "mitre_attack_enterprise_vertex_collection",
                "mitre_cwe_edge_collection",
                "mitre_cwe_vertex_collection",
                "mitre_capec_vertex_collection",
            ],
        )


@pytest.mark.parametrize(
    "args",
    [
        ("--modes", "bad-mode-here"),
        ("--modes", "mode1", "--database", "db-here"),
        [],
    ],
)
def test_parse_args__bad_args(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["prog", *args])
    with pytest.raises(SystemExit):
        parse_arguments()


@pytest.mark.parametrize(
    "args,expected_dict",
    [
        (
            ["--modes", "cwe-capec", "--database", "mydb"],
            dict(
                modes=["cwe-capec"],
                ignore_embedded_relationships=None,
                database="mydb",
                version=None,
            ),
        ),
        (
            ["--modes", "cwe-capec,capec-attack", "--database", "mydb"],
            dict(
                modes=["cwe-capec", "capec-attack"],
                ignore_embedded_relationships=None,
                database="mydb",
                version=None,
            ),
        ),
        (
            ["--relationship", "cwe-capec,capec-attack", "--database", "mydb"],
            dict(
                modes=["cwe-capec", "capec-attack"],
                ignore_embedded_relationships=None,
                database="mydb",
                version=None,
            ),
        ),
        (
            ["--modes", "cwe-capec", "--database", "mydb", "--version", "1.0.1"],
            dict(
                modes=["cwe-capec"],
                ignore_embedded_relationships=None,
                database="mydb",
                version="1.0.1",
            ),
        ),
    ],
)
def test_parse_args(monkeypatch, args, expected_dict):
    monkeypatch.setattr(sys, "argv", ["prog", *args])
    retval = parse_arguments()
    assert retval.__dict__ == expected_dict
