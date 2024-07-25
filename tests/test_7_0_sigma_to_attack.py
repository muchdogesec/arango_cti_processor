import os
import subprocess
import unittest
from arango import ArangoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD")
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL")

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Run the arango_cti_processor.py script
        subprocess.run([
            "python3", "arango_cti_processor.py",
            "--database", "arango_cti_processor_standard_tests_database",
            "--relationship", "sigma-attack",
            "--stix2arango_note", "test07",
            "--ignore_embedded_relationships", "false"
        ], check=True)
        
        cls.db = client.db('arango_cti_processor_standard_tests_database', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)

    def run_query(self, query):
        cursor = self.db.aql.execute(query)
        return [count for count in cursor]

    # should still return 2 objects b/c these never update
    def test_01_auto_imported_objects(self):
        query = """
          FOR doc IN sigma_rules_vertex_collection
            FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 2 Expects 14437 results (see test-data-research.md for why)
    def test_02_check_generated_relationships(self):
        query = """
        RETURN LENGTH(
          FOR doc IN sigma_rules_edge_collection
            FILTER doc._is_latest == true
            AND doc.relationship_type == "detects"
            AND doc._arango_cti_processor_note == "sigma-attack"
            AND doc.object_marking_refs == [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
            ]
            RETURN [doc]
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [14437], f"Expected 14437 documents, but found {result_count}.")

# check relationships for indicator--49150a4c-d831-51fa-9f61-aede5570a969 has two ATT&CK references, `attack.t1016` and `attack.discovery`, which should create 5 SROs
# Enterprise
# * `attack.t1016` (`course-of-action--684feec3-f9ba-4049-9d8f-52d52f3e0e40`)
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--49150a4c-d831-51fa-9f61-aede5570a969+mitre_attack_enterprise_vertex_collection/course-of-action--684feec3-f9ba-4049-9d8f-52d52f3e0e40` = `relationship--00ce4b29-1c68-59cf-9ec4-49fe9e7eaff6`
# * `attack.t1016` (`attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0`)
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--49150a4c-d831-51fa-9f61-aede5570a969+mitre_attack_enterprise_vertex_collection/attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0` = `relationship--3dce842a-fd66-562f-81c0-d2351f787d0a`
# * `attack.discovery` (TA0007) (`x-mitre-tactic--c17c5845-175e-4421-9713-829d0573dbc9`)
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--49150a4c-d831-51fa-9f61-aede5570a969+mitre_attack_enterprise_vertex_collection/x-mitre-tactic--c17c5845-175e-4421-9713-829d0573dbc9` = `relationship--fecb5591-2cc4-5557-9092-06f3ae5728ea`
# ICS
# * `attack.t1016`: none
# * `attack.discovery` (TA0102) (`x-mitre-tactic--696af733-728e-49d7-8261-75fdc590f453`)
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--49150a4c-d831-51fa-9f61-aede5570a969+mitre_attack_ics_vertex_collection/x-mitre-tactic--696af733-728e-49d7-8261-75fdc590f453` = `relationship--6f7e0e11-02fb-5ad0-b0fd-b04deab4c8d6`
# Mobile
# * `attack.t1016`: none
# * `attack.discovery` (TA0032) (`x-mitre-tactic--d418cdeb-1b9f-4a6b-a15d-2f89f549f8c1`)
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--49150a4c-d831-51fa-9f61-aede5570a969+mitre_attack_mobile_vertex_collection/x-mitre-tactic--d418cdeb-1b9f-4a6b-a15d-2f89f549f8c1` = `relationship--f549d020-7c11-528d-ab25-1cb868fc2f6e`

    def test_03_check_relationship_gen_for_object1(self):
        query = """
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == true
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--49150a4c-d831-51fa-9f61-aede5570a969"
              RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "relationship--00ce4b29-1c68-59cf-9ec4-49fe9e7eaff6",
            "relationship--3dce842a-fd66-562f-81c0-d2351f787d0a",
            "relationship--fecb5591-2cc4-5557-9092-06f3ae5728ea",
            "relationship--6f7e0e11-02fb-5ad0-b0fd-b04deab4c8d6",
            "relationship--f549d020-7c11-528d-ab25-1cb868fc2f6e"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# `indicator--f85a0947-bf4e-5e19-b67e-6652a1277f61` has a links to:
#* `attack.defense_evasion`:
#  * `x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a` (enterprise) 
#`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--f85a0947-bf4e-5e19-b67e-6652a1277f61+mitre_attack_enterprise_vertex_collection/x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a` = `relationship--b4fcb79e-3b00-5796-9275-ae57b68eb1b9`
#  * `x-mitre-tactic--987cda6d-eb77-406b-bf68-bcb5f3d2e1df` (mobile)
#`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--f85a0947-bf4e-5e19-b67e-6652a1277f61+mitre_attack_mobile_vertex_collection/x-mitre-tactic--987cda6d-eb77-406b-bf68-bcb5f3d2e1df` = `relationship--26c3ff4e-4456-56fd-9317-7fcdf89cb921`
#* `attack.t1218.001`: `attack-pattern--a6937325-9321-4e2e-bb2b-3ed2d40b2a9d` (enterprise)
#`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--f85a0947-bf4e-5e19-b67e-6652a1277f61+mitre_attack_enterprise_vertex_collection/attack-pattern--a6937325-9321-4e2e-bb2b-3ed2d40b2a9d` = `relationship--e6581f5a-6b0e-52ea-a2c4-3df520f91929`

    def test_04_check_relationship_gen_for_object2(self):
        query = """
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == true
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--f85a0947-bf4e-5e19-b67e-6652a1277f61"
              RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "relationship--b4fcb79e-3b00-5796-9275-ae57b68eb1b9",
            "relationship--26c3ff4e-4456-56fd-9317-7fcdf89cb921",
            "relationship--e6581f5a-6b0e-52ea-a2c4-3df520f91929"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")


#Expect 16 results
#indicator--afcd1642-b090-511f-8805-78f54d9aae3a has links to:
#* attack.persistence
#  * x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92 (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_enterprise_vertex_collection/x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92` = `relationship--e8fb72b4-8751-54c6-92c6-849112993ec6`
#  * x-mitre-tactic--78f1d2ae-a579-44c4-8fc5-3e1775c73fac (ics)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_ics_vertex_collection/x-mitre-tactic--78f1d2ae-a579-44c4-8fc5-3e1775c73fac` = `relationship--8b18b7ef-3de5-5485-bf92-0240cb243eb0`
#  * x-mitre-tactic--363bbeff-bb2a-4734-ac74-d6d37202fe54 (mobile)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_mobile_vertex_collection/x-mitre-tactic--363bbeff-bb2a-4734-ac74-d6d37202fe54` = `relationship--b6e298d4-387d-530a-b9e6-579f6e4af4f8`
#* attack.defense_evasion
#  * x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_enterprise_vertex_collection/x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a` = `relationship--8240d7bd-9ada-5836-bc86-0f7e7f6e4295`
#  * x-mitre-tactic--987cda6d-eb77-406b-bf68-bcb5f3d2e1df (mobile)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_mobile_vertex_collection/x-mitre-tactic--987cda6d-eb77-406b-bf68-bcb5f3d2e1df` = `relationship--ace89f1f-4779-5524-aba8-cc6b7fa17602`
#* attack.command_and_control
#  * x-mitre-tactic--f72804c5-f15a-449e-a5da-2eecd181f813 (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_enterprise_vertex_collection/x-mitre-tactic--f72804c5-f15a-449e-a5da-2eecd181f813` = `relationship--d3bfffe5-c415-51e8-9db2-764ff8891750`
#  * x-mitre-tactic--97c8ff73-bd14-4b6c-ac32-3d91d2c41e3f (ics)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_ics_vertex_collection/x-mitre-tactic--97c8ff73-bd14-4b6c-ac32-3d91d2c41e3f` = `relationship--ca26dfa4-239f-5eca-a2ff-691d93b4f54a`
#  * x-mitre-tactic--3f660805-fa2e-42e8-8851-57f9e9b653e3 (mobile)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_mobile_vertex_collection/x-mitre-tactic--3f660805-fa2e-42e8-8851-57f9e9b653e3` = `relationship--a3491141-ac05-5285-82eb-d1a1b1050d97`
#* attack.g0049
#  * intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_enterprise_vertex_collection/intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d` = `relationship--d41b495b-c1bf-5d9e-87ab-e0da2fee67ee`
#  * intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d (ics) DUPLICATE IDs but collections are different so should generate data
#* attack.t1053.005
#  * attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9 (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_enterprise_vertex_collection/attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9` = `relationship--d0e3ff99-61ff-5838-940b-23a3624fc8b1`
#* attack.s0111
#  * tool--c9703cd3-141c-43a0-a926-380082be5d04 (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_enterprise_vertex_collection/tool--c9703cd3-141c-43a0-a926-380082be5d04` = `relationship--0eb75854-13b4-50c0-bee5-f6d47bc2b95d`
#* attack.t1543.003
#  * attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32 (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_enterprise_vertex_collection/attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32` = `relationship--e97d2d67-acda-5331-a293-7e8c56590fc6`
#* attack.t1112
#  * course-of-action--ed202147-4026-4330-b5bd-1e8dfa8cf7cc (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_enterprise_vertex_collection/course-of-action--ed202147-4026-4330-b5bd-1e8dfa8cf7cc` = `relationship--d933f949-bde7-557d-aedb-84b36a8ffaa8`
#  * attack-pattern--57340c81-c025-4189-8fa0-fc7ede51bae4 (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_enterprise_vertex_collection/attack-pattern--57340c81-c025-4189-8fa0-fc7ede51bae4` = `relationship--4a278cef-9b6d-5a5b-9e68-5ed9288e3c57`
#* attack.t1071.004
#  * attack-pattern--1996eef1-ced3-4d7f-bf94-33298cabbf72 (enterprise)
###`2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--afcd1642-b090-511f-8805-78f54d9aae3a+mitre_attack_enterprise_vertex_collection/attack-pattern--1996eef1-ced3-4d7f-bf94-33298cabbf72` = `relationship--6b4b873b-4447-5b5f-95df-b3894d203ff0`

    def test_05_check_relationship_gen_for_object3(self):
        query = """
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == true
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--afcd1642-b090-511f-8805-78f54d9aae3a"
              RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "relationship--e8fb72b4-8751-54c6-92c6-849112993ec6",
            "relationship--8b18b7ef-3de5-5485-bf92-0240cb243eb0",
            "relationship--b6e298d4-387d-530a-b9e6-579f6e4af4f8",
            "relationship--8240d7bd-9ada-5836-bc86-0f7e7f6e4295",
            "relationship--ace89f1f-4779-5524-aba8-cc6b7fa17602",
            "relationship--d3bfffe5-c415-51e8-9db2-764ff8891750",
            "relationship--ca26dfa4-239f-5eca-a2ff-691d93b4f54a",
            "relationship--a3491141-ac05-5285-82eb-d1a1b1050d97",
            "relationship--d41b495b-c1bf-5d9e-87ab-e0da2fee67ee",
            "relationship--d0e3ff99-61ff-5838-940b-23a3624fc8b1",
            "relationship--0eb75854-13b4-50c0-bee5-f6d47bc2b95d",
            "relationship--e97d2d67-acda-5331-a293-7e8c56590fc6",
            "relationship--d933f949-bde7-557d-aedb-84b36a8ffaa8",
            "relationship--4a278cef-9b6d-5a5b-9e68-5ed9288e3c57",
            "relationship--6b4b873b-4447-5b5f-95df-b3894d203ff0",
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# no updates to the objects should have happened yet

    def test_06_check_no_updates(self):
        query = """
            RETURN LENGTH(
              FOR doc IN sigma_rules_edge_collection
                FILTER doc._is_latest == false
                AND doc._arango_cti_processor_note == "sigma-attack"
                RETURN doc
            )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
