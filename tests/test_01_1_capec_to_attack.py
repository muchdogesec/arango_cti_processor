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
TEST_MODE = "capec-attack"
IGNORE_EMBEDDED_RELATIONSHIPS = "true"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("mitre_capec", "tests/files/actip-capec-attack-update-1.json"),
            ], database="arango_cti_processor_standard_tests", delete_db=False, 
            host_url=ARANGODB_HOST_URL, password=ARANGODB_PASSWORD, username=ARANGODB_USERNAME)
        print(f'======Test bundles uploaded successfully======')
        # Run the arango_cti_processor.py script
        subprocess.run([
            "python3", "arango_cti_processor.py",
            "--database", TESTS_DATABASE,
            "--relationship", TEST_MODE,
            "--ignore_embedded_relationships", IGNORE_EMBEDDED_RELATIONSHIPS
        ], check=True)
        print(f'======arango_cti_processor run successfully======')
        
        cls.db = client.db('arango_cti_processor_standard_tests_database', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)

    def run_query(self, query):
        cursor = self.db.aql.execute(query)
        return [count for count in cursor]

# Test 1 still expect still on 2 results (as no versioned objects should be created for auto imports -- b/c md5's are the same)

    def test_01_auto_imported_objects(self):
        query = """
          FOR doc IN mitre_capec_vertex_collection
            FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# test 2 CAPEC-158 attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a update check

    def test_02_update_capec158(self):
        query = """
            RETURN COUNT(
                FOR doc IN mitre_capec_vertex_collection
                  FILTER doc.id == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
                  RETURN doc
            )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [2], f"Expected 2 documents, but found {result_count}.")

# test 3 CAPEC-158 attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a old version

    def test_03_update_capec158_old_version(self):
        query = """
            RETURN COUNT(
                FOR doc IN mitre_capec_vertex_collection
                  FILTER doc.id == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
                  AND doc._is_latest == false
                  RETURN doc
            )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [1], f"Expected 1 documents, but found {result_count}.")

# test 4 check relationships for old version of CAPEC-158. Should return 4 results, because old version of `attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a` had 2 ATT&CK references (but each one resolves to 1 attack-pattern, and 1 course-of-action).

    def test_04_update_capec158_old_version_relationships(self):
        query = """
            RETURN COUNT(
                FOR doc IN mitre_capec_edge_collection
                  FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
                  AND doc._is_latest == false
                  AND doc._arango_cti_processor_note == "capec-attack"
                  AND doc._is_ref == false
                  RETURN doc
            )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [4], f"Expected 4 documents, but found {result_count}.")

# test 5 Should return 3 results, because new version of `attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a` has 3 ATT&CK references -- the new one with one link to an attack-pattern

    def test_05_update_capec158_new_version_relationships(self):
        query = """
            RETURN COUNT(
                FOR doc IN mitre_capec_edge_collection
                  FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
                  AND doc._is_latest == true
                  AND doc._arango_cti_processor_note == "capec-attack"
                  AND doc._is_ref == false
                  RETURN doc
            )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [5], f"Expected 5 documents, but found {result_count}.")

# test 6 test the relationship ids are correct

# object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a+mitre_attack_enterprise_vertex_collection/attack-pattern--3257eb21-f9a7-4430-8de1-d8b6e288f529` = c1e846eb-6463-5933-bfd0-0c2cbe655e7f
# object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a+mitre_attack_enterprise_vertex_collection/course-of-action--46b7ef91-4e1d-43c5-a2eb-00fa9444f6f4` = d896e414-2eb0-51dc-a6f0-0fa003ef6bb5
# object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a+mitre_attack_enterprise_vertex_collection/attack-pattern--dd43c543-bb85-4a6f-aa6e-160d90d06a49` = 1ac8370b-3815-5f6d-baf7-a39080fe3a35
# object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a+mitre_attack_enterprise_vertex_collection/course-of-action--e8d22ec6-2236-48de-954b-974d17492782` = d39341ee-e330-507f-85f8-4087e4ad86e6
# object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a+mitre_attack_enterprise_vertex_collection/attack-pattern--d21bb61f-08ad-4dc1-b001-81ca6cb79954` = 7f0b0170-59ff-5b3e-86e8-2fdb8650ad14


    def test_06_update_capec158_check_relationship_ids(self):
        query = """
          FOR doc IN mitre_capec_edge_collection
            FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
            AND doc._is_latest == true
            AND doc._arango_cti_processor_note == "capec-attack"
            AND doc._is_ref == false
            SORT doc.id ASC
            RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "relationship--1ac8370b-3815-5f6d-baf7-a39080fe3a35",
            "relationship--7f0b0170-59ff-5b3e-86e8-2fdb8650ad14",
            "relationship--c1e846eb-6463-5933-bfd0-0c2cbe655e7f",
            "relationship--d39341ee-e330-507f-85f8-4087e4ad86e6",
            "relationship--d896e414-2eb0-51dc-a6f0-0fa003ef6bb5"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# test 7 this is the new CAPEC-999 object

    def test_07_new_capec999(self):
        query = """
        RETURN COUNT(
            FOR doc IN mitre_capec_edge_collection
              FILTER doc.source_ref == "attack-pattern--39b37ebd-276c-48e7-b152-d94a29599f4b"
              AND doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc._is_ref == false
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [1], f"Expected 1 documents, but found {result_count}.")

# test 8 this is the new CAPEC-999 object, so should be no old objects

    def test_08_new_capec999_update(self):
        query = """
        RETURN COUNT(
            FOR doc IN mitre_capec_edge_collection
              FILTER doc.source_ref == "attack-pattern--39b37ebd-276c-48e7-b152-d94a29599f4b"
              AND doc._is_latest == false
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc._is_ref == false
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
