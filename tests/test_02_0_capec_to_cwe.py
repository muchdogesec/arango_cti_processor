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
TEST_MODE = "capec-cwe"
STIX2ARANGO_NOTE = __name__
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("mitre_capec", "tests/files/stix-capec-v3_9.json"),
                ("mitre_cwe", "tests/files/cwe-bundle-v4_13.json"),
            ], database="arango_cti_processor_standard_tests", delete_db=True, 
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

    # test 1 Should return 5 objects, the newest version, and 4 old ones.
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

    # test 2 checks all objects generated correctly
    def test_02_arango_cti_processor_note(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_edge_collection
          FILTER doc._arango_cti_processor_note == "capec-cwe"
          AND doc._is_ref == false
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [1212], f"Expected 1212 documents, but found {result_count}.")

    # test 3 checks the correct number of objects are generated, and that they are assigned the correct properties by the script
    def test_03_correct_object_properties(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_edge_collection
            FILTER doc.type == "relationship"
            AND doc.relationship_type == "exploits"
            AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
            AND doc.object_marking_refs == [
              "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
              "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
            ]
            AND doc._arango_cti_processor_note == "capec-cwe"
            AND doc._is_ref == false
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [1212], f"Expected 1212 documents, but found {result_count}.")

    # test 4 To check objects are created as expected, you can pick a CAPEC object with CWE references and then check all the SROs for CWE are generated for it, as follows...
    # e.g. [CAPEC-112](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1.json) which has links to: CWE-330 (weakness--5c1cf10b-dc31-5536-a1b5-dc5094e7f4b2), CWE-326 (weakness--3f87bca2-8785-543e-906e-cf2adb753c31), CWE-521 (weakness--de02e88c-42c5-5ddf-b5d1-1c8aeac79926)
    def test_04_correct_relationship_capec112(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-cwe"
              AND doc.source_ref == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
              AND doc._is_ref == false
              SORT doc.target_ref ASC
              RETURN doc.target_ref
        """
        result_count = self.run_query(query)
        expected_ids = [
            "weakness--3f87bca2-8785-543e-906e-cf2adb753c31",
            "weakness--5c1cf10b-dc31-5536-a1b5-dc5094e7f4b2",
            "weakness--de02e88c-42c5-5ddf-b5d1-1c8aeac79926"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 5 is extension of test 4 to check id generation:
    # object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploits+mitre_capec_vertex_collection/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1+mitre_cwe_vertex_collection/weakness--5c1cf10b-dc31-5536-a1b5-dc5094e7f4b2` = b7327c21-681e-509f-8dd0-9d8a18b64612
    # object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploits+mitre_capec_vertex_collection/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1+mitre_cwe_vertex_collection/weakness--3f87bca2-8785-543e-906e-cf2adb753c31` = aefc359a-9eb8-5675-b190-4ce8334b58df
    # object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `exploits+mitre_capec_vertex_collection/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1+mitre_cwe_vertex_collection/weakness--de02e88c-42c5-5ddf-b5d1-1c8aeac79926` = f6282d95-2a8e-583c-9561-70a67426c751
    def test_05_correct_relationship_capec112_ids(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-cwe"
              AND doc.source_ref == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
              AND doc._is_ref == false
              SORT doc.id ASC
              RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "relationship--aefc359a-9eb8-5675-b190-4ce8334b58df",
            "relationship--b7327c21-681e-509f-8dd0-9d8a18b64612",
            "relationship--f6282d95-2a8e-583c-9561-70a67426c751"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# no updates to the objects should have happened yet

    def test_06_check_no_updates(self):
        query = """
            RETURN LENGTH(
              FOR doc IN mitre_capec_edge_collection
                FILTER doc._is_latest == false
                AND doc._arango_cti_processor_note == "capec-cwe"
                AND doc._is_ref == false
                RETURN doc
            )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

    def test_07_check_object_description_properties(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
                FILTER doc._arango_cti_processor_note == "capec-cwe"
                AND doc.id == "relationship--6dfedb11-9d14-5d0e-bd69-9739dd188b2f"
                AND doc._is_ref == false
                RETURN doc.description
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
          "CAPEC-1 exploits CWE-276"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
