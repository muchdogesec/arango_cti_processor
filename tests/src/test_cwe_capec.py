from unittest.mock import patch
from arango_cti_processor.managers.cwe_capec import CweCapec


CWE_MATCHES = [
    [
        {
            "ext_id": "CWE-94",
            "name": "CWE-94 (Improper Control of Generation of Code ('Code Injection'))",
            "ref_ids": ["CAPEC-242", "CAPEC-35", "CAPEC-77"],
            "modified": "2025-04-03T00:00:00.000Z",
            "id": "weakness--bd696f33-1ee8-59eb-9d30-3bdee9553805",
            "created": "2006-07-19T00:00:00.000Z",
        },
        {
            "ext_id": "CWE-276",
            "name": "CWE-276 (Incorrect Default Permissions)",
            "ref_ids": ["CAPEC-1", "CAPEC-127", "CAPEC-81"],
            "modified": "2023-06-29T00:00:00.000Z",
            "id": "weakness--bfa2f40d-b5f0-505e-9ac5-92adfe0b6bd8",
            "created": "2006-07-19T00:00:00.000Z",
        },
        {
            "ext_id": "CWE-99",
            "name": "CWE-99 (Improper Control of Resource Identifiers ('Resource Injection'))",
            "ref_ids": ["CAPEC-10", "CAPEC-240", "CAPEC-75"],
            "modified": "2023-10-26T00:00:00.000Z",
            "id": "weakness--c80522e0-a937-5dcb-846a-d5aefc1dc552",
            "created": "2006-07-19T00:00:00.000Z",
        },
        {
            "ext_id": "CWE-862",
            "name": "CWE-862 (Missing Authorization)",
            "ref_ids": ["CAPEC-665"],
            "modified": "2024-11-19T00:00:00.000Z",
            "id": "weakness--e0f27140-5b49-51ea-aef0-0fed0dd082cf",
            "created": "2011-05-24T00:00:00.000Z",
        },
        {
            "ext_id": "CWE-269",
            "name": "CWE-269 (Improper Privilege Management)",
            "ref_ids": ["CAPEC-122", "CAPEC-233", "CAPEC-58"],
            "modified": "2024-11-19T00:00:00.000Z",
            "id": "weakness--eb90af25-bcf1-5a0e-a162-a149ed58712a",
            "created": "2006-07-19T00:00:00.000Z",
        },
    ]
]


def test_get_object_chunks(session_processor):
    manager = CweCapec(session_processor, version="1.9")
    matches = list(manager.get_object_chunks())
    for match in matches[0]:
        assert match.pop("_id").startswith(manager.collection + "/" + match["id"])

    assert matches == CWE_MATCHES


def test_get_object_chunks__latest(session_processor):
    manager = CweCapec(session_processor)
    matches = list(manager.get_object_chunks())
    for match in matches[0]:
        assert match.pop("_id").startswith(manager.collection + "/" + match["id"])
    assert matches == CWE_MATCHES


def test_get_object_chunks__bad_version(session_processor):
    manager = CweCapec(session_processor, version="123.1.1")
    matches = list(manager.get_object_chunks())
    assert matches == []


def test_do_process(session_processor):
    manager = CweCapec(session_processor)
    manager.CHUNK_SIZE = 2  # only use first two
    objects = list(manager.get_object_chunks())[0]

    with patch(
        "arango_cti_processor.managers.cwe_capec.STIXRelationManager.do_process"
    ) as mock_super_do_process:
        manager.do_process(objects)

        mock_super_do_process.assert_called_once()
        assert mock_super_do_process.call_args[0][0] == objects


def test_relate_single(session_processor):
    manager = CweCapec(session_processor)
    manager.secondary_objects = manager.get_secondary_objects(
        ["CAPEC-122", "CAPEC-233", "CAPEC-58"]
    )  # skip 3 capecs to simulate missing
    retval = manager.relate_single(
        {
            "ext_id": "CWE-269",
            "name": "CWE-269 (Improper Privilege Management)",
            "ref_ids": ["CAPEC-122", "CAPEC-233", "CAPEC-58"],
            "modified": "2024-11-19T00:00:00.000Z",
            "id": "weakness--eb90af25-bcf1-5a0e-a162-a149ed58712a",
            "created": "2006-07-19T00:00:00.000Z",
            "_id": "mitre_cwe_vertex_collection/weakness--eb90af25-bcf1-5a0e-a162-a149ed58712a",
        }
    )
    print(retval)
    for match in retval:
        assert match.pop("_to").startswith(
            manager.secondary_collection + "/" + match["target_ref"]
        )
    assert retval == [
        {
            "id": "relationship--46ca6a0d-fa42-5b7e-bff7-700206e0111a",
            "type": "relationship",
            "created": "2006-07-19T00:00:00.000Z",
            "modified": "2024-11-19T00:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "weakness--eb90af25-bcf1-5a0e-a162-a149ed58712a",
            "target_ref": "attack-pattern--fd669b7d-0e79-473c-9808-a860dfb0c871",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            ],
            "description": "CWE-269 (Improper Privilege Management) is exploited using CAPEC-122 (Privilege Abuse)",
            "_arango_cti_processor_note": "cwe-capec",
            "_from": "mitre_cwe_vertex_collection/weakness--eb90af25-bcf1-5a0e-a162-a149ed58712a",
            "_is_ref": False,
            "external_references": [
                {
                    "source_name": "cwe",
                    "external_id": "CWE-269",
                    "url": "http://cwe.mitre.org/data/definitions/269.html",
                },
                {
                    "source_name": "capec",
                    "external_id": "CAPEC-122",
                    "url": "https://capec.mitre.org/data/definitions/122.html",
                },
            ],
        },
        {
            "id": "relationship--8ec03e50-d6d1-518e-bf62-490872780e3d",
            "type": "relationship",
            "created": "2006-07-19T00:00:00.000Z",
            "modified": "2024-11-19T00:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "weakness--eb90af25-bcf1-5a0e-a162-a149ed58712a",
            "target_ref": "attack-pattern--c05fff04-b965-4a11-9c18-379dac31969f",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            ],
            "description": "CWE-269 (Improper Privilege Management) is exploited using CAPEC-233 (Privilege Escalation)",
            "_arango_cti_processor_note": "cwe-capec",
            "_from": "mitre_cwe_vertex_collection/weakness--eb90af25-bcf1-5a0e-a162-a149ed58712a",
            "_is_ref": False,
            "external_references": [
                {
                    "source_name": "cwe",
                    "external_id": "CWE-269",
                    "url": "http://cwe.mitre.org/data/definitions/269.html",
                },
                {
                    "source_name": "capec",
                    "external_id": "CAPEC-233",
                    "url": "https://capec.mitre.org/data/definitions/233.html",
                },
            ],
        },
        {
            "id": "relationship--6df6caab-9092-5128-b10d-7b8e0c4057e4",
            "type": "relationship",
            "created": "2006-07-19T00:00:00.000Z",
            "modified": "2024-11-19T00:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "weakness--eb90af25-bcf1-5a0e-a162-a149ed58712a",
            "target_ref": "attack-pattern--74bac7d9-693d-40d2-82bf-eb132f13bcaf",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            ],
            "description": "CWE-269 (Improper Privilege Management) is exploited using CAPEC-58 (Restful Privilege Elevation)",
            "_arango_cti_processor_note": "cwe-capec",
            "_from": "mitre_cwe_vertex_collection/weakness--eb90af25-bcf1-5a0e-a162-a149ed58712a",
            "_is_ref": False,
            "external_references": [
                {
                    "source_name": "cwe",
                    "external_id": "CWE-269",
                    "url": "http://cwe.mitre.org/data/definitions/269.html",
                },
                {
                    "source_name": "capec",
                    "external_id": "CAPEC-58",
                    "url": "https://capec.mitre.org/data/definitions/58.html",
                },
            ],
        },
    ]
