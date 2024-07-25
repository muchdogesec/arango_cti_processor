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
          FOR doc IN sigma_rules_edge_collection
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
#  * x-mitre-tactic--78f1d2ae-a579-44c4-8fc5-3e1775c73fac (ics)
#  * x-mitre-tactic--363bbeff-bb2a-4734-ac74-d6d37202fe54 (mobile)
#* attack.defense_evasion
#  * x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a (enterprise)
#  * x-mitre-tactic--987cda6d-eb77-406b-bf68-bcb5f3d2e1df (mobile)
#* attack.command_and_control
#  * x-mitre-tactic--f72804c5-f15a-449e-a5da-2eecd181f813 (enterprise)
#  * x-mitre-tactic--97c8ff73-bd14-4b6c-ac32-3d91d2c41e3f (ics)
#  * x-mitre-tactic--3f660805-fa2e-42e8-8851-57f9e9b653e3 (mobile)
#* attack.g0049
#  * intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d (enterprise)
#  * intrusion-set--4ca1929c-7d64-4aab-b849-badbfc0c760d (ics) DUPLICATE IDs but collections are different so should generate data
#* attack.t1053.005
#  * attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9 (enterprise)
#* attack.s0111
#  * tool--c9703cd3-141c-43a0-a926-380082be5d04 (enterprise)
#* attack.t1543.003
#  * attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32 (enterprise)
#* attack.t1112
#  * course-of-action--ed202147-4026-4330-b5bd-1e8dfa8cf7cc (enterprise)
#  * attack-pattern--57340c81-c025-4189-8fa0-fc7ede51bae4 (enterprise)
#* attack.t1071.004
#  * attack-pattern--1996eef1-ced3-4d7f-bf94-33298cabbf72 (enterprise)

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
            ""
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")






if __name__ == '__main__':
    unittest.main()
