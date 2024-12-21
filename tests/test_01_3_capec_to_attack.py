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
                ("mitre_capec", "tests/files/actip-capec-attack-update-3.json"),
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

# test 1 Should return 4 objects, the newest version, and 3 old ones.

    def test_01_updated_capec158(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_vertex_collection
              FILTER doc.id == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [4], f"Expected 4 documents, but found {result_count}.")

# test 2 Should return 15 results. oldest version (1.0) of CAPEC158 had 4 ATT&CK references, old version 1.1 had 5 ATT&CK references, old version 1.2 had 6

    def test_02_updated_capec158_old_relationships(self):
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
        self.assertEqual(result_count, [15], f"Expected 15 documents, but found {result_count}.")

# test 3 Should return 4 results because the new object has both T1040 (1 coa, 1 attack pattern) and T1111 (1 coa, 1 attack pattern)

    def test_03_updated_capec158_new_relationships(self):
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
        self.assertEqual(result_count, [4], f"Expected 4 documents, but found {result_count}.")

# test 4 is extensions of test 3 but checks target ids

    def test_04_updated_capec158_new_relationships_check_ids(self):
        query = """
        FOR doc IN mitre_capec_edge_collection
            FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
            AND doc._is_latest == true
            AND doc._arango_cti_processor_note == "capec-attack"
            AND doc._is_ref == false
            RETURN doc.target_ref
        """
        result_count = self.run_query(query)
        expected_ids = [
            "course-of-action--46b7ef91-4e1d-43c5-a2eb-00fa9444f6f4", # Enterprise T1040
            "attack-pattern--3257eb21-f9a7-4430-8de1-d8b6e288f529", # Enterprise T1040
            "course-of-action--e8d22ec6-2236-48de-954b-974d17492782", # Enterprise T1111
            "attack-pattern--dd43c543-bb85-4a6f-aa6e-160d90d06a49", # Enterprise T1111
        ]
        self.assertEqual(set(result_count), set(expected_ids), f"Expected {expected_ids}, but found {result_count}.")

# test 5 check t1650 (attack-pattern--d21bb61f-08ad-4dc1-b001-81ca6cb79954). this only exists in updates 1.1. and 1.2.

    def test_05_updated_capec158_new_relationships_t1650(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_edge_collection
              FILTER doc.target_ref == "attack-pattern--d21bb61f-08ad-4dc1-b001-81ca6cb79954"
              AND doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              AND doc._is_latest == false
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc._is_ref == false
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [2], f"Expected 2 documents, but found {result_count}.")

# test 6 is extension of test 5, but checks there is no latest version

    def test_06_updated_capec158_new_relationships_t1650_new(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_edge_collection
              FILTER doc.target_ref == "attack-pattern--d21bb61f-08ad-4dc1-b001-81ca6cb79954"
              AND doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              AND doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc._is_ref == false
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
