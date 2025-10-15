from unittest.mock import patch

import pytest
from arango_cti_processor.managers.technique_tactic import TechniqueTactic


def test_get_object_chunks(session_processor):
    manager = TechniqueTactic(
        session_processor, version="17.1", collection="mitre_attack_enterprise"
    )
    matches = list(manager.get_object_chunks())
    matches = matches and matches[0]

    for match in matches:
        assert match.pop("_id").startswith(manager.collection + "/" + match["id"])
    assert matches == [
        {
            "created": "2022-09-30T18:50:14.351Z",
            "id": "attack-pattern--0533ab23-3f7d-463f-9bd8-634d27e4dee1",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
            ],
            "modified": "2025-04-15T19:58:03.051Z",
            "name": "Embedded Payloads",
            "type": "attack-pattern",
            "ext_ref_dict": {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1027/009",
                "external_id": "T1027.009",
            },
            "attack_id": "T1027.009",
        },
        {
            "created": "2020-01-30T13:58:14.373Z",
            "id": "attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "privilege-escalation",
                },
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
            ],
            "modified": "2025-04-15T19:58:37.690Z",
            "name": "Abuse Elevation Control Mechanism",
            "type": "attack-pattern",
            "ext_ref_dict": {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1548",
                "external_id": "T1548",
            },
            "attack_id": "T1548",
        },
        {
            "created": "2019-12-19T20:21:21.669Z",
            "id": "attack-pattern--791481f8-e96a-41be-b089-a088763083d4",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
            ],
            "modified": "2025-04-15T19:58:43.347Z",
            "name": "Component Firmware",
            "type": "attack-pattern",
            "ext_ref_dict": {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1542/002",
                "external_id": "T1542.002",
            },
            "attack_id": "T1542.002",
        },
        {
            "created": "2017-05-31T21:31:04.710Z",
            "id": "attack-pattern--7bc57495-ea59-4380-be31-a64af124ef18",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "discovery"}
            ],
            "modified": "2025-04-15T19:58:44.118Z",
            "name": "File and Directory Discovery",
            "type": "attack-pattern",
            "ext_ref_dict": {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1083",
                "external_id": "T1083",
            },
            "attack_id": "T1083",
        },
        {
            "created": "2020-03-12T20:43:53.998Z",
            "id": "attack-pattern--9e8b28c9-35fe-48ac-a14d-e6cc032dcbcd",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "privilege-escalation",
                },
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
            ],
            "modified": "2025-04-16T20:37:18.533Z",
            "name": "Services File Permissions Weakness",
            "type": "attack-pattern",
            "ext_ref_dict": {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1574/010",
                "external_id": "T1574.010",
            },
            "attack_id": "T1574.010",
        },
        {
            "created": "2021-10-12T20:02:31.866Z",
            "id": "attack-pattern--b22e5153-ac28-4cc6-865c-2054e36285cb",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
            ],
            "modified": "2025-04-16T20:37:19.185Z",
            "name": "Resource Forking",
            "type": "attack-pattern",
            "ext_ref_dict": {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1564/009",
                "external_id": "T1564.009",
            },
            "attack_id": "T1564.009",
        },
        {
            "created": "2021-05-20T12:20:42.219Z",
            "id": "attack-pattern--d4dc46e3-5ba5-45b9-8204-010867cacfcb",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
            ],
            "modified": "2025-04-15T19:59:12.085Z",
            "name": "HTML Smuggling",
            "type": "attack-pattern",
            "ext_ref_dict": {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1027/006",
                "external_id": "T1027.006",
            },
            "attack_id": "T1027.006",
        },
        {
            "created": "2020-02-11T19:01:56.887Z",
            "id": "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"},
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
            ],
            "modified": "2025-04-15T19:59:21.746Z",
            "name": "Modify Authentication Process",
            "type": "attack-pattern",
            "ext_ref_dict": {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1556",
                "external_id": "T1556",
            },
            "attack_id": "T1556",
        },
        {
            "created": "2018-04-18T17:59:24.739Z",
            "id": "attack-pattern--fe926152-f431-4baf-956c-4ad3cb0bf23b",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
            ],
            "modified": "2025-04-15T19:59:24.778Z",
            "name": "Exploitation for Defense Evasion",
            "type": "attack-pattern",
            "ext_ref_dict": {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1211",
                "external_id": "T1211",
            },
            "attack_id": "T1211",
        },
    ]


def test_do_process(session_processor):
    manager = TechniqueTactic(
        session_processor, version="17.1", collection="mitre_attack_enterprise"
    )
    manager.CHUNK_SIZE = 2  # only use first two
    objects = list(manager.get_object_chunks())[0]

    with patch(
        "arango_cti_processor.managers.cwe_capec.STIXRelationManager.do_process"
    ) as mock_super_do_process:
        manager.do_process(objects)

        mock_super_do_process.assert_called_once()
        assert mock_super_do_process.call_args[0][0] == objects


def test_relate_single(session_processor):
    manager = TechniqueTactic(
        session_processor, version="17.1", collection="mitre_attack_enterprise"
    )
    manager.get_objects_from_db()
    retval = manager.relate_single(
        {
            "_id": "mitre_attack_enterprise_vertex_collection/attack-pattern--791481f8-e96a-41be-b089-a088763083d4+2025-10-07T11:06:12.949317Z",
            "_key": "attack-pattern--791481f8-e96a-41be-b089-a088763083d4+2025-10-07T11:06:12.949317Z",
            "created": "2019-12-19T20:21:21.669Z",
            "id": "attack-pattern--791481f8-e96a-41be-b089-a088763083d4",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
            ],
            "modified": "2025-04-15T19:58:43.347Z",
            "name": "Component Firmware",
            "type": "attack-pattern",
            "ext_ref_dict": {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1542/002",
                "external_id": "T1542.002",
            },
            "attack_id": "T1542.002",
        }
    )
    print(retval)
    for match in retval:
        assert match.pop("_to").startswith(
            "mitre_attack_enterprise_vertex_collection/" + match["target_ref"]
        )
    print("")
    print(retval)
    assert retval == [
        {
            "id": "relationship--b6e157c3-bb08-5b5f-b7a8-fa488f3995fe",
            "type": "relationship",
            "created": "2019-12-19T20:21:21.669Z",
            "modified": "2025-04-15T19:58:43.347Z",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--791481f8-e96a-41be-b089-a088763083d4",
            "target_ref": "x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            ],
            "description": "Technique T1542.002 (Component Firmware) belongs to Tactic TA0003 (Persistence)",
            "_arango_cti_processor_note": "technique-tactic",
            "_from": "mitre_attack_enterprise_vertex_collection/attack-pattern--791481f8-e96a-41be-b089-a088763083d4+2025-10-07T11:06:12.949317Z",
            "_is_ref": False,
            "external_references": (
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1542/002",
                    "external_id": "T1542.002",
                },
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/tactics/TA0003",
                    "external_id": "TA0003",
                },
            ),
        },
        {
            "id": "relationship--7ba00a7e-beeb-5e4d-ac17-6f4c549b29bc",
            "type": "relationship",
            "created": "2019-12-19T20:21:21.669Z",
            "modified": "2025-04-15T19:58:43.347Z",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--791481f8-e96a-41be-b089-a088763083d4",
            "target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            ],
            "description": "Technique T1542.002 (Component Firmware) belongs to Tactic TA0005 (Defense Evasion)",
            "_arango_cti_processor_note": "technique-tactic",
            "_from": "mitre_attack_enterprise_vertex_collection/attack-pattern--791481f8-e96a-41be-b089-a088763083d4+2025-10-07T11:06:12.949317Z",
            "_is_ref": False,
            "external_references": (
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1542/002",
                    "external_id": "T1542.002",
                },
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/tactics/TA0005",
                    "external_id": "TA0005",
                },
            ),
        },
    ]


def test_make_relations(session_processor):
    TechniqueTactic.make_relations(
        version="17.1",
        collection="mitre_attack_enterprise",
        stix2arango_note="my-note-make-relations",
        database=session_processor.db.name,
    )
    object_ids = session_processor.execute_raw_query(
        """
            FOR d IN mitre_attack_enterprise_edge_collection
            FILTER d._stix2arango_note == 'my-note-make-relations'
            RETURN KEEP(d, 'id', 'relationship_type', 'source_ref', 'target_ref')
            """,
    )
    print(object_ids)
    assert object_ids == [
        {
            "id": "relationship--18223612-9e0d-5acb-bbc2-294f146af9fb",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--9e8b28c9-35fe-48ac-a14d-e6cc032dcbcd",
            "target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
        },
        {
            "id": "relationship--1c82139e-1093-5dfb-a73f-3fef79071596",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--fe926152-f431-4baf-956c-4ad3cb0bf23b",
            "target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
        },
        {
            "id": "relationship--2958a131-8318-5c78-a7d0-e425e851c77a",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--7bc57495-ea59-4380-be31-a64af124ef18",
            "target_ref": "x-mitre-tactic--c17c5845-175e-4421-9713-829d0573dbc9",
        },
        {
            "id": "relationship--35b46155-c5bf-5eb8-b3b6-b2c194ddcbdd",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84",
            "target_ref": "x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92",
        },
        {
            "id": "relationship--59f3ae31-06ff-5568-b855-4174a3377168",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--b22e5153-ac28-4cc6-865c-2054e36285cb",
            "target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
        },
        {
            "id": "relationship--67344507-8d53-5bfe-b567-26db458b1c38",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--9e8b28c9-35fe-48ac-a14d-e6cc032dcbcd",
            "target_ref": "x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92",
        },
        {
            "id": "relationship--7b45fdcc-ec96-550f-bb01-b0427a61b069",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--9e8b28c9-35fe-48ac-a14d-e6cc032dcbcd",
            "target_ref": "x-mitre-tactic--5e29b093-294e-49e9-a803-dab3d73b77dd",
        },
        {
            "id": "relationship--7ba00a7e-beeb-5e4d-ac17-6f4c549b29bc",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--791481f8-e96a-41be-b089-a088763083d4",
            "target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
        },
        {
            "id": "relationship--91093c09-e17b-528e-bc8f-ed5ffbfa3636",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84",
            "target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
        },
        {
            "id": "relationship--9f8df88e-d8d4-541d-b246-154fe3f9048d",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b",
            "target_ref": "x-mitre-tactic--5e29b093-294e-49e9-a803-dab3d73b77dd",
        },
        {
            "id": "relationship--aee724fc-124c-57c0-9c25-6987c138131b",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--0533ab23-3f7d-463f-9bd8-634d27e4dee1",
            "target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
        },
        {
            "id": "relationship--afef3745-c2bd-55ac-b497-c9c07de798e2",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--d4dc46e3-5ba5-45b9-8204-010867cacfcb",
            "target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
        },
        {
            "id": "relationship--b6e157c3-bb08-5b5f-b7a8-fa488f3995fe",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--791481f8-e96a-41be-b089-a088763083d4",
            "target_ref": "x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92",
        },
        {
            "id": "relationship--bb8c2137-0d4a-51ef-bc67-597c2841a861",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84",
            "target_ref": "x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263",
        },
        {
            "id": "relationship--e6e0620e-a0af-5e10-af5e-950c589e5970",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b",
            "target_ref": "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
        },
    ]
