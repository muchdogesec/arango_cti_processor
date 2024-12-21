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
STIX2ARANGO_NOTE = __name__.split('.')[-1]
IGNORE_EMBEDDED_RELATIONSHIPS = "true"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("mitre_capec", "tests/files/actip-stix-capec-v3_9.json"),
                ("mitre_attack_enterprise", "tests/files/actip-enterprise-attack-14_1.json"),
                ("mitre_attack_ics", "tests/files/actip-ics-attack-14_1.json"),
                ("mitre_attack_mobile", "tests/files/actip-mobile-attack-14_1.json"),
            ], database="arango_cti_processor_standard_tests", delete_db=True, 
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

    def test_01_auto_imported_objects(self):
        query = """
          FOR doc IN mitre_capec_vertex_collection
            FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

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
          FILTER doc._arango_cti_processor_note == "capec-attack"
          AND doc._is_ref == false
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [346], f"Expected 346 documents, but found {result_count}.")

    # checks the corret number of objects are generated, and that they are assigned the correct properties by the script

    def test_03_correct_object_properties(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_edge_collection
            FILTER doc.type == "relationship"
            AND doc.relationship_type == "technique"
            AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
            AND doc.object_marking_refs == [
              "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
              "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
            ]
            AND doc._arango_cti_processor_note == "capec-attack"
            AND doc._is_ref == false
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [346], f"Expected 346 documents, but found {result_count}.")

    # test 4 checks [CAPEC-695](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001.json) -> T1195.001

    def test_04_correct_relationship_capec695(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc.source_ref == "attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001"
              AND doc._is_ref == false
              RETURN doc.target_ref
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "attack-pattern--191cc6af-1bb2-4344-ab5f-28e496638720"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 5 is extension of test 4 to check id generation: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` value: `technique+mitre_capec_vertex_collection/attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001+mitre_attack_enterprise_vertex_collection/attack-pattern--191cc6

    def test_05_relationship_id_generation695(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc.source_ref == "attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001"
              AND doc._is_ref == false
              RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "relationship--34d58beb-5d4c-5899-b3aa-2a0d5995e82d"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 6 checks [CAPEC-233](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--c05fff04-b965-4a11-9c18-379dac31969f.json) -> T1548

    def test_06_correct_relationship_capec233(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc.source_ref == "attack-pattern--c05fff04-b965-4a11-9c18-379dac31969f"
              AND doc._is_ref == false
              RETURN doc.target_ref
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 7 is extension of test 6 to check id generation: `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--c05fff04-b965-4a11-9c18-379dac31969f+mitre_attack_enterprise_vertex_collection/attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b` = bc0d764e-f1ba-55ff-b871-7735ec140789

    def test_07_relationship_id_generation233(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc.source_ref == "attack-pattern--c05fff04-b965-4a11-9c18-379dac31969f"
              AND doc._is_ref == false
              RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "relationship--bc0d764e-f1ba-55ff-b871-7735ec140789"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 8 checks [CAPEC-13](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed.json -> T1562.003, T1574.006, T1574.007

    def test_08_correct_relationship_capec13(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
                FILTER doc._is_latest == true
                AND doc._arango_cti_processor_note == "capec-attack"
                AND doc.source_ref == "attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed"
                AND doc._is_ref == false
                SORT doc.target_ref ASC
                RETURN doc.target_ref
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "attack-pattern--0c2d00da-7742-49e7-9928-4514e5075d32", # T1574.007
            "attack-pattern--633a100c-b2c9-41bf-9be5-905c1b16c825", # T1574.006
            "attack-pattern--8f504411-cb96-4dac-a537-8d2bb7679c59" # T1562.003
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 9 is extension of test 8 to check id generation:
    # object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed+mitre_attack_enterprise_vertex_collection/attack-pattern--8f504411-cb96-4dac-a537-8d2bb7679c59` = c1100173-c259-52a1-926d-48919b067224
    # object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed+mitre_attack_enterprise_vertex_collection/attack-pattern--633a100c-b2c9-41bf-9be5-905c1b16c825` = d66bcc7d-19c0-5c2c-a7f7-44b13d6af09c
    # object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed+mitre_attack_enterprise_vertex_collection/attack-pattern--0c2d00da-7742-49e7-9928-4514e5075d32` = 23bd53cf-0f53-53e3-8ba1-92b4077bd460

    def test_09_relationship_id_generation13(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc.source_ref == "attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed"
              AND doc._is_ref == false
              SORT doc.target_ref ASC
              RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "relationship--23bd53cf-0f53-53e3-8ba1-92b4077bd460", # T1574.007
            "relationship--d66bcc7d-19c0-5c2c-a7f7-44b13d6af09c", # T1574.006
            "relationship--c1100173-c259-52a1-926d-48919b067224" # T1562.003
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # no updates to the objects should have happened yet

    def test_10_check_no_updates(self):
        query = """
            RETURN LENGTH(
              FOR doc IN mitre_capec_edge_collection
                FILTER doc._is_latest == false
                AND doc._arango_cti_processor_note == "capec-attack"
                AND doc._is_ref == false
                RETURN doc
            )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

    def test_11_check_object_description_properties(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
                FILTER doc._arango_cti_processor_note == "capec-attack"
                AND doc.id == "relationship--9100fbed-3b33-5b7d-8517-8dc54ad5444b"
                AND doc._is_ref == false
                RETURN doc.description
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
          "CAPEC-1 (Accessing Functionality Not Properly Constrained by ACLs) uses technique T1574.010 (Services File Permissions Weakness)"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()