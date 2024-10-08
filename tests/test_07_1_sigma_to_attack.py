import os
import subprocess
import unittest
from arango import ArangoClient
from dotenv import load_dotenv
from stix2arango.stix2arango import Stix2Arango

from .upload import make_uploads

# Load environment variables
load_dotenv()

ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME", "root")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD", "")
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL", "http://127.0.0.1:8529")
TESTS_DATABASE = "arango_cti_processor_standard_tests_database"
TEST_MODE = "sigma-attack"
STIX2ARANGO_NOTE = __name__.split('.')[-1]
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("sigma_rules", "tests/files/sigma-rule-update-1.json"),
            ], database="arango_cti_processor_standard_tests", delete_db=False, 
            host_url=ARANGODB_HOST_URL, password=ARANGODB_PASSWORD, username=ARANGODB_USERNAME, stix2arango_note=STIX2ARANGO_NOTE)
        print(f'======Test bundles uploaded successfully======')
        # Run the arango_cti_processor.py script
        subprocess.run([
            "python3", "arango_cti_processor.py",
            "--database", TESTS_DATABASE,
            "--relationship", TEST_MODE,
            "--stix2arango_note", STIX2ARANGO_NOTE,
            "--ignore_embedded_relationships", IGNORE_EMBEDDED_RELATIONSHIPS
        ], check=True)
        print(f'======arango_cti_processor run successfully======')
        
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

    def test_02_check_generated_relationships(self):
        query = """
        FOR doc in sigma_rules_edge_collection
          FILTER doc._arango_cti_processor_note == "sigma-attack"
          AND doc._is_latest == true
          AND doc._is_ref == false
          COLLECT type = SPLIT(doc.target_ref, "--")[0] into docs
          RETURN {[type]: COUNT(docs[*].doc)}
        """
        result_count = self.run_query(query)
        expected_ids = [
              {
                "attack-pattern": 3544
              },
              {
                "intrusion-set": 42
              },
              {
                "tool": 60
              },
              {
                "x-mitre-tactic": 10476
              }
            ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# this is all the old objects in indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf updated in this test (4) in total
    def test_03_check_generated_relationships_old(self):
        query = """
        FOR doc in sigma_rules_edge_collection
          FILTER doc._arango_cti_processor_note == "sigma-attack"
          AND doc._is_latest == false
          AND doc._is_ref == false
          COLLECT type = SPLIT(doc.target_ref, "--")[0] into docs
          RETURN {[type]: COUNT(docs[*].doc)}
        """
        result_count = self.run_query(query)
        expected_ids = [
              {
                "attack-pattern": 1
              },
              {
                "tool": 1
              },
              {
                "x-mitre-tactic": 2
              }
            ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

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
#                    "source_name": "mitre-attack",
#                    "url": "https://attack.mitre.org/techniques/T1543.003",
#                    "external_id": "T1543.003"
#                },
#        {
#          "source_name": "mitre-attack",
#          "url": "https://attack.mitre.org/software/S0002",
#          "external_id": "S0002"
#        },
# Enterprise
# * credential_access TA0006 x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf+mitre_attack_enterprise_vertex_collection/x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263` = 7b0e4488-59ff-50bc-b4b6-9c79e09ce8c8

# Mobile
# * credential_access TA0031 x-mitre-tactic--6fcb36b8-3776-483b-8699-42215714fb10
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf+mitre_attack_mobile_vertex_collection/x-mitre-tactic--6fcb36b8-3776-483b-8699-42215714fb10` = 0f5bef42-7b2d-55c2-8c15-36d0bceced1d

# Enterprise
# * T1003.001 LSASS Memory attack-pattern--65f2d882-3f41-4d48-8a06-29af77ec9f90
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf+mitre_attack_enterprise_vertex_collection/attack-pattern--65f2d882-3f41-4d48-8a06-29af77ec9f90` = e119b459-c4c7-5ce3-bdd5-1caedb9f6d4b

# * S0002 Mimikatz tool--afc079f3-c0ea-4096-b75d-3f05338b7f60
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf+mitre_attack_enterprise_vertex_collection/tool--afc079f3-c0ea-4096-b75d-3f05338b7f60` = `d7e0a492-db21-5021-a7fb-ec8d31acb051`

# * T1543.003 Windows service attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32
#   * `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `detects+sigma_rules_vertex_collection/indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf+mitre_attack_enterprise_vertex_collection/attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32` = `c63ea028-890c-5b15-aced-4cb3dcf71b09`

    def test_04_check_relationship_gen_for_object1(self):
        query = """
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == true
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf"
              AND doc._is_ref == false
              SORT doc.id ASC
              RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "relationship--0f5bef42-7b2d-55c2-8c15-36d0bceced1d",
            "relationship--7b0e4488-59ff-50bc-b4b6-9c79e09ce8c8",
            "relationship--c63ea028-890c-5b15-aced-4cb3dcf71b09",
            "relationship--d7e0a492-db21-5021-a7fb-ec8d31acb051",
            "relationship--e119b459-c4c7-5ce3-bdd5-1caedb9f6d4b"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# should return 4 results (as test 7.0 has 4 sros generated)

    def test_05_check_relationship_gen_for_object1_old(self):
        query = """
        RETURN COUNT(
          FOR doc IN sigma_rules_edge_collection
              FILTER doc._is_latest == false
              AND doc.relationship_type == "detects"
              AND doc.source_ref == "indicator--1a7e070a-64cb-5d4f-aff4-8e5fdcd72edf"
              AND doc._is_ref == false
              RETURN doc.id
            )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [4], f"Expected 4 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()