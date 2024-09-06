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
TEST_MODE = "cve-cpe"
STIX2ARANGO_NOTE = __name__.split('.')[-1]
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("nvd_cve", "tests/files/cve-cpe-bundle-with-cves-update-2.json"),
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
          FOR doc IN nvd_cve_vertex_collection
            FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = [
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
            "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
        ]
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # Should return 3 results, the new and 2 old versions
    def test_02_test_update_to_indicator(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_vertex_collection
            FILTER doc.id == "indicator--570304ae-02cf-542b-ab7a-77e7ada2f48e"
              RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [3], f"Expected 3 documents, but found {result_count}.")

    # Should return 0 results after update  (note even though pattern is populated in test, we use the vulnerable / not_vulnerable property to gen this data)
    def test_03_test_relationships_to_cpes_new(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
          FILTER doc._arango_cti_processor_note == "cve-cpe"
          AND doc.relationship_type == "pattern-contains"
          AND doc._is_latest == true
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

    # should return 11 (same as 6.0 + 6.1 results)  (note even though pattern is populated in test, we use the vulnerable / not_vulnerable property to gen this data)
    def test_04_test_relationships_to_cpes_old(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
          FILTER doc._arango_cti_processor_note == "cve-cpe"
          AND doc.relationship_type == "pattern-contains"
          AND doc._is_latest == false
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [11], f"Expected 11 documents, but found {result_count}.")

    # now 0 cpes vulnerable
    def test_05_test_relationships_to_vulnerable_cpes_new(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
          FILTER doc._arango_cti_processor_note == "cve-cpe"
          AND doc.relationship_type == "is-vulnerable"
          AND doc._is_latest == true
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

    # 6.0 + 6.1
    def test_06_test_relationships_to_vulnerable_cpes_old(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
          FILTER doc._arango_cti_processor_note == "cve-cpe"
          AND doc.relationship_type == "is-vulnerable"
          AND doc._is_latest == false
            RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [3], f"Expected 3 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()