import os
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

    def setUp(self):
        self.db = client.db('arango_cti_processor_standard_tests_database', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)

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

    def test_02_arango_cti_processor_note(self):
        query = """
        RETURN COUNT(
          FOR doc IN mitre_capec_edge_collection
          FILTER doc._arango_cti_processor_note == "capec-attack"
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [346], f"Expected 346 documents, but found {result_count}.")

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
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [338], f"Expected 338 documents, but found {result_count}.")

    def test_04_correct_relationship_capec695(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc.source_ref == "attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001"
              RETURN doc.target_ref
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "attack-pattern--191cc6af-1bb2-4344-ab5f-28e496638720"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    def test_05_relationship_id_generation695(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc.source_ref == "attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001"
              RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "relationship--34d58beb-5d4c-5899-b3aa-2a0d5995e82d"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    def test_06_correct_relationship_capec233(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc.source_ref == "attack-pattern--c05fff04-b965-4a11-9c18-379dac31969f"
              RETURN doc.target_ref
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    def test_07_relationship_id_generation233(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc.source_ref == "attack-pattern--c05fff04-b965-4a11-9c18-379dac31969f"
              RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "relationship--bc0d764e-f1ba-55ff-b871-7735ec140789"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    def test_08_correct_relationship_capec13(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc.source_ref == "attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed"
              RETURN doc.target_ref
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "attack-pattern--8f504411-cb96-4dac-a537-8d2bb7679c59", # T1562.003
            "attack-pattern--633a100c-b2c9-41bf-9be5-905c1b16c825", # T1574.006
            "attack-pattern--0c2d00da-7742-49e7-9928-4514e5075d32" # T1574.007
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    def test_09_relationship_id_generation13(self):
        query = """
            FOR doc IN mitre_capec_edge_collection
              FILTER doc._is_latest == true
              AND doc._arango_cti_processor_note == "capec-attack"
              AND doc.source_ref == "attack-pattern--f190e1b3-e8d6-4aef-817c-b3e7782e2aed"
              RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "relationship--c1100173-c259-52a1-926d-48919b067224", # T1562.003
            "relationship--d66bcc7d-19c0-5c2c-a7f7-44b13d6af09c", # T1574.006
            "relationship--23bd53cf-0f53-53e3-8ba1-92b4077bd460" # T1574.007
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    def test_10_check_no_updates(self):
        query = """
            RETURN LENGTH(
              FOR doc IN mitre_capec_edge_collection
                FILTER doc._is_latest == false
                AND doc._arango_cti_processor_note == "capec-attack"
                RETURN doc
            )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
