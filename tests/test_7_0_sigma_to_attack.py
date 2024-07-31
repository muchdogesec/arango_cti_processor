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

    # test 2 Expects 15546 results (see test-data-research.md for why)
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
        self.assertEqual(result_count, [15546], f"Expected 15546 documents, but found {result_count}.")

# check relationships for indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf has 3 ATT&CK references (but credential_access is in two domains, so 4 total sros expected), 
#        {
#          "source_name": "mitre-attack",
#          "description": "tactic",
#          "external_id": "credential_access"
#        },
#        {
#          "source_name": "mitre-attack",
#          "url": "https://attack.mitre.org/techniques/T1003.001",
#          "external_id": "T1003.001"
#        },
#        {
#          "source_name": "mitre-attack",
#          "url": "https://attack.mitre.org/software/S0002",
#          "external_id": "S0002"
#        },
# Enterprise
# * credential_access TA0002 x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf+mitre_attack_enterprise_vertex_collection/x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5` = `86ac99cc-d4c4-56fb-ae8b-720c3772503a`
# * T1003.001 attack-pattern--65f2d882-3f41-4d48-8a06-29af77ec9f90
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf+mitre_attack_enterprise_vertex_collection/attack-pattern--65f2d882-3f41-4d48-8a06-29af77ec9f90` = `e119b459-c4c7-5ce3-bdd5-1caedb9f6d4b`
# * S0002 tool--afc079f3-c0ea-4096-b75d-3f05338b7f60
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf+mitre_attack_enterprise_vertex_collection/tool--afc079f3-c0ea-4096-b75d-3f05338b7f60` = `d7e0a492-db21-5021-a7fb-ec8d31acb051`
# Mobile
# * credential_access TA0035 x-mitre-tactic--7a0d25d3-f0c0-40bf-bf90-c743871b19ba
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf+mitre_attack_mobile_vertex_collection/x-mitre-tactic--7a0d25d3-f0c0-40bf-bf90-c743871b19ba` = `96495af9-cd33-5191-95ab-d098b7ef2f5e`

    def test_03_check_relationship_gen_for_object1(self):
        query = """
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == true
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf"
              RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "relationship--86ac99cc-d4c4-56fb-ae8b-720c3772503a",
            "relationship--e119b459-c4c7-5ce3-bdd5-1caedb9f6d4b",
            "relationship--d7e0a492-db21-5021-a7fb-ec8d31acb051",
            "relationship--96495af9-cd33-5191-95ab-d098b7ef2f5e"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# should return no results as no old versions of this object (this is first test)

    def test_04_check_relationship_gen_for_object1_old(self):
        query = """
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == false
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf"
              RETURN doc.id
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()