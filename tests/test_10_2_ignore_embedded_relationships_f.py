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
                ("nvd_cve", "tests/files/condensed_cpe_bundle-update-2.json"),
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

## removes one object from indicator--5d45090c-57fe-543e-96a9-bbd5ea9d6cb6
## so now only 2 sros again -- same as 6.9
## now expect only 18 SROs (as the one object removed has 3 _is_ref)

    def test_01_count_is_ref_latest(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
            FILTER doc._arango_cti_processor_note == "cve-cpe"
            AND doc._is_ref == true
            AND doc._is_latest == true
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [18], f"Expected 18 documents, but found {result_count}.")

# was 6 in 6.1, now 9 to account for the SRO marked as _is_latest = false (which has 3 _is_ref relationships)

    def test_02_count_is_ref_false(self):
        query = """
        RETURN COUNT (
            FOR doc IN nvd_cve_edge_collection
                FILTER doc._arango_cti_processor_note == "cve-cpe"
                AND doc._is_ref == true
                AND doc._is_latest == false
                SORT doc.id
                RETURN [doc]
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [9], f"Expected 9 documents, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()