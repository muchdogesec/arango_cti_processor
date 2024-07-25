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
            "--relationship", "capec-attack",
            "--stix2arango_note", "test01",
            "--ignore_embedded_relationships", "false"
        ], check=True)
        
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
                  RETURN doc
            )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [5], f"Expected 5 documents, but found {result_count}.")

# test 6 test the relationship ids are correct

    def test_06_update_capec158_check_relationship_ids(self):
        query = """
          FOR doc IN mitre_capec_edge_collection
            FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
            AND doc._is_latest == true
            AND doc._arango_cti_processor_note == "capec-attack"
                RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            # Add the expected IDs here
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
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
