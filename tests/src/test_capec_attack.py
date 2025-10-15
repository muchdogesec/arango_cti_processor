from unittest.mock import patch

import pytest
from arango_cti_processor.managers.capec_attack import CapecAttack

@pytest.mark.parametrize(
    "version,expected_ids",
    [
        (
            None,
            {
                "CAPEC-1",
                "CAPEC-122",
                "CAPEC-571",
                "CAPEC-115",
                "CAPEC-233",
                "CAPEC-35",
                "CAPEC-665",
                "CAPEC-655",
                "CAPEC-114",
                "CAPEC-127",
                "CAPEC-572",
            },
        ),  # latest
        ("3.7", {"CAPEC-571", "CAPEC-115", "CAPEC-655", "CAPEC-114", "CAPEC-572"}),
        (
            "3.9",
            {"CAPEC-1", "CAPEC-122", "CAPEC-233", "CAPEC-35", "CAPEC-665", "CAPEC-127"},
        ),
        ("13.91", []),
    ],
)
def test_get_object_chunks(session_processor, version, expected_ids):
    manager = CapecAttack(session_processor, version=version)
    matches = list(manager.get_object_chunks())
    matches = matches and matches[0]
    assert {m["ext_id"] for m in matches} == set(expected_ids)


def test_do_process(session_processor):
    manager = CapecAttack(session_processor)
    manager.CHUNK_SIZE = 2  # only use first two
    objects = list(manager.get_object_chunks())[0]

    with patch(
        "arango_cti_processor.managers.cwe_capec.STIXRelationManager.do_process"
    ) as mock_super_do_process:
        manager.do_process(objects)

        mock_super_do_process.assert_called_once()
        assert mock_super_do_process.call_args[0][0] == objects


def test_relate_single(session_processor):
    manager = CapecAttack(session_processor)
    manager.secondary_objects = manager.get_secondary_objects(
        ["T1211", "T1542.002", "T1556"]
    )
    retval = manager.relate_single(
        {
            "ext_id": "CAPEC-665",
            "name": "CAPEC-665 (Exploitation of Thunderbolt Protection Flaws)",
            "ref_ids": ["T1211", "T1542.002", "T1556"],
            "modified": "2022-09-29T00:00:00.000Z",
            "id": "attack-pattern--4317ab6c-93e4-4c5a-a814-0cd2752c61b9",
            "created": "2021-06-24T00:00:00.000Z",
            "_id": "mitre_capec_vertex_collection/attack-pattern--4317ab6c-93e4-4c5a-a814-0cd2752c61b9+2025-10-07T11:06:12.086697Z",
        }
    )
    print(retval)
    for match in retval:
        assert match.pop("_to").startswith(
            manager.secondary_collection + "/" + match["target_ref"]
        )
    assert retval == [
        {
            "id": "relationship--64d4ac58-5428-553b-8191-b6adab4c6f4a",
            "type": "relationship",
            "created": "2021-06-24T00:00:00.000Z",
            "modified": "2022-09-29T00:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--4317ab6c-93e4-4c5a-a814-0cd2752c61b9",
            "target_ref": "attack-pattern--fe926152-f431-4baf-956c-4ad3cb0bf23b",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            ],
            "description": "CAPEC-665 (Exploitation of Thunderbolt Protection Flaws) uses technique T1211 (Exploitation for Defense Evasion)",
            "_arango_cti_processor_note": "capec-attack",
            "_from": "mitre_capec_vertex_collection/attack-pattern--4317ab6c-93e4-4c5a-a814-0cd2752c61b9+2025-10-07T11:06:12.086697Z",
            "_is_ref": False,
            "external_references": [
                {
                    "source_name": "capec",
                    "external_id": "CAPEC-665",
                    "url": "https://capec.mitre.org/data/definitions/665.html",
                },
                {"source_name": "mitre-attack", "external_id": "T1211"},
            ],
        },
        {
            "id": "relationship--f41b470c-eb33-5ac7-a1db-4851f659422c",
            "type": "relationship",
            "created": "2021-06-24T00:00:00.000Z",
            "modified": "2022-09-29T00:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--4317ab6c-93e4-4c5a-a814-0cd2752c61b9",
            "target_ref": "attack-pattern--791481f8-e96a-41be-b089-a088763083d4",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            ],
            "description": "CAPEC-665 (Exploitation of Thunderbolt Protection Flaws) uses technique T1542.002 (Component Firmware)",
            "_arango_cti_processor_note": "capec-attack",
            "_from": "mitre_capec_vertex_collection/attack-pattern--4317ab6c-93e4-4c5a-a814-0cd2752c61b9+2025-10-07T11:06:12.086697Z",
            "_is_ref": False,
            "external_references": [
                {
                    "source_name": "capec",
                    "external_id": "CAPEC-665",
                    "url": "https://capec.mitre.org/data/definitions/665.html",
                },
                {"source_name": "mitre-attack", "external_id": "T1542.002"},
            ],
        },
        {
            "id": "relationship--89c2945c-e646-55f3-a15b-1cc2b358376e",
            "type": "relationship",
            "created": "2021-06-24T00:00:00.000Z",
            "modified": "2022-09-29T00:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--4317ab6c-93e4-4c5a-a814-0cd2752c61b9",
            "target_ref": "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            ],
            "description": "CAPEC-665 (Exploitation of Thunderbolt Protection Flaws) uses technique T1556 (Modify Authentication Process)",
            "_arango_cti_processor_note": "capec-attack",
            "_from": "mitre_capec_vertex_collection/attack-pattern--4317ab6c-93e4-4c5a-a814-0cd2752c61b9+2025-10-07T11:06:12.086697Z",
            "_is_ref": False,
            "external_references": [
                {
                    "source_name": "capec",
                    "external_id": "CAPEC-665",
                    "url": "https://capec.mitre.org/data/definitions/665.html",
                },
                {"source_name": "mitre-attack", "external_id": "T1556"},
            ],
        },
    ]
