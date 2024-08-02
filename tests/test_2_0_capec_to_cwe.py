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
STIX2ARANGO_NOTE = "test02"
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("mitre_capec", "tests/files/stix-capec-v3_9.json"),
                ("mitre_cwe", "tests/files/cwe-bundle-v4_13.json"),
            ], database="arango_cti_processor_standard_tests", delete_db=True, 
            host_url=ARANGODB_HOST_URL, password=ARANGODB_PASSWORD, username=ARANGODB_USERNAME)
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
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [1212], f"Expected 1212 documents, but found {result_count}.")

    # test 4 To check objects are created as expected, you can pick a CAPEC object with CWE references and then check all the SROs for CWE are generated for it, as follows...
    # e.g. [CAPEC-112](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1.json) which has links to: CWE-330 (weakness--e72563af-bb4e-59d9-926c-95344c1ef7e0), CWE-326 (weakness--611422c2-1201-50dc-8c94-0ddf62565555), CWE-521 (weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5)
    def test_04_correct_relationship_capec112(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-cwe"
              AND doc.source_ref == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
              RETURN doc.target_ref
        """
        result_count = self.run_query(query)
        expected_ids = [
            "weakness--e72563af-bb4e-59d9-926c-95344c1ef7e0",
            "weakness--611422c2-1201-50dc-8c94-0ddf62565555",
            "weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 5 is extension of test 4 to check id generation:
    # object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1+mitre_cwe_vertex_collection/weakness--e72563af-bb4e-59d9-926c-95344c1ef7e0` = d931a94d-039a-57b7-a089-21d80bc3b1de
    # object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1+mitre_cwe_vertex_collection/weakness--611422c2-1201-50dc-8c94-0ddf62565555` = c98b705d-747f-5b5b-870a-0fae14bcfd14
    # object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1+mitre_cwe_vertex_collection/weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5` = 8eaf77d7-9bd5-5ccd-9a46-b2c002d4b47b
    def test_05_correct_relationship_capec112_ids(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-cwe"
              AND doc.source_ref == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
              RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "relationship--d931a94d-039a-57b7-a089-21d80bc3b1de",
            "relationship--c98b705d-747f-5b5b-870a-0fae14bcfd14",
            "relationship--8eaf77d7-9bd5-5ccd-9a46-b2c002d4b47b"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# no updates to the objects should have happened yet

    def test_06_check_no_updates(self):
        query = """
            RETURN LENGTH(
              FOR doc IN mitre_capec_edge_collection
                FILTER doc._is_latest == false
                AND doc._arango_cti_processor_note == "capec-cwe"
                RETURN doc
            )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")
if __name__ == '__main__':
    unittest.main()
