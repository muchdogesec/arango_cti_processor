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
                ("mitre_capec", "tests/files/actip-capec-attack-update-4.json"),
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

    # test 1 Should return 5 objects, the newest version, and 4 old ones.
    def test_01_updated_capec158(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_vertex_collection
              FILTER doc.id == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [5], f"Expected 5 documents, but found {result_count}.")

    # test 2 Should return 19 results. oldest version (1.0) of CAPEC158 had 4 ATT&CK references, old version 1.1 had 5 ATT&CK references, old version 1.2 had 6, 1.3 had 4
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
        self.assertEqual(result_count, [19], f"Expected 19 documents, but found {result_count}.")

    # test 3 Should return 6 results because the new object has 6 ATT&CK references (2 with 2 ATT&CK objects, 2 with 1 ATT&CK objects)
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
        self.assertEqual(result_count, [6], f"Expected 6 documents, but found {result_count}.")

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
            "attack-pattern--d21bb61f-08ad-4dc1-b001-81ca6cb79954", # Enterprise T1650
            "course-of-action--46b7ef91-4e1d-43c5-a2eb-00fa9444f6f4", # Enterprise T1040
            "attack-pattern--3257eb21-f9a7-4430-8de1-d8b6e288f529", # Enterprise T1040
            "course-of-action--e8d22ec6-2236-48de-954b-974d17492782", # Enterprise T1111
            "attack-pattern--dd43c543-bb85-4a6f-aa6e-160d90d06a49", # Enterprise T1111
            "attack-pattern--9e8b28c9-35fe-48ac-a14d-e6cc032dcbcd" # Enterprise T1574.010
        ]
        self.assertEqual(set(result_count), set(expected_ids), f"Expected {expected_ids}, but found {result_count}.")

    # test 5 check T1040 only. Should return 10 objects total for relationship to T1040 -- attack pattern 4 old objects (from 1.0, 1.1, 1.2, 1.3) and 1 new object from this update 1.3. + same again for coa
    def test_05_updated_capec158_new_relationships_t1040(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_edge_collection
              FILTER (doc.target_ref == "course-of-action--46b7ef91-4e1d-43c5-a2eb-00fa9444f6f4"
              OR doc.target_ref == "attack-pattern--3257eb21-f9a7-4430-8de1-d8b6e288f529")
              AND doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc._is_ref == false
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [10], f"Expected 10 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
