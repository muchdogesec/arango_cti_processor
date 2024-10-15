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
TEST_MODE = "attack-capec"
STIX2ARANGO_NOTE = __name__.split('.')[-1]
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("mitre_attack_enterprise", "tests/files/enterprise-attack-14_1.json"),
                ("mitre_attack_ics", "tests/files/ics-attack-14_1.json"),
                ("mitre_attack_mobile", "tests/files/mobile-attack-14_1.json"),
                ("mitre_capec", "tests/files/stix-capec-v3_9.json"),
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

    # 2 auto imported objects in each collection
    def test_01_auto_imported_objects(self):
        query = """
        RETURN COUNT(
          FOR doc IN UNION(
                (FOR d IN mitre_attack_enterprise_vertex_collection RETURN d),
                (FOR d IN mitre_attack_ics_vertex_collection RETURN d),
                (FOR d IN mitre_attack_mobile_vertex_collection RETURN d)
            )
            FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [6], f"Expected 6 documents, but found {result_count}.")

    # test 2 check all sros generated correctly
    def test_02_count_generated_sros(self):
        query = """
        RETURN COUNT(
          FOR doc IN UNION(
            (FOR d IN mitre_attack_enterprise_edge_collection RETURN d),
            (FOR d IN mitre_attack_ics_edge_collection RETURN d),
            (FOR d IN mitre_attack_mobile_edge_collection RETURN d)
        )
          FILTER doc.relationship_type == "relies-on"
          AND doc._arango_cti_processor_note == "attack-capec"
          AND doc._is_ref == false
          RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

    def test_03_correct_object_properties(self):
        query = """
        RETURN COUNT(
          FOR doc IN UNION(
            (FOR d IN mitre_attack_enterprise_edge_collection RETURN d),
            (FOR d IN mitre_attack_ics_edge_collection RETURN d),
            (FOR d IN mitre_attack_mobile_edge_collection RETURN d)
        )
          FILTER doc.relationship_type == "relies-on"
          AND doc.created_by_ref == "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
          AND doc.object_marking_refs == [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
          ]
          AND doc._is_ref == false
          RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

    # To check objects are created as expected, you can pick a ATT&CK object with CAPEC references and then check all the SROs for CAPECs are generated for it, as follows...
    # T1162: `attack-pattern--36675cd3-fe00-454c-8516-aebecacbe9d9` (Enterprise Vertex) has a link to CAPEC-564 (`attack-pattern--b63b2869-11e6-4849-8ddf-ae2557bf554b`)
    def test_04_checkT1162_relationships(self):
        query = """
        RETURN COUNT(
        FOR doc IN UNION(
            (FOR d IN mitre_attack_enterprise_edge_collection RETURN d),
            (FOR d IN mitre_attack_ics_edge_collection RETURN d),
            (FOR d IN mitre_attack_mobile_edge_collection RETURN d)
        )
          FILTER doc.relationship_type == "relies-on"
          AND doc.source_ref == "attack-pattern--36675cd3-fe00-454c-8516-aebecacbe9d9"
          AND doc._is_ref == false
          RETURN doc
        )
        """
        result_count = self.run_query(query)
        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

    # test 5 is an extension of test 4 but checks relationship ids
    # `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `relies-on+mitre_attack_enterprise_vertex_collection/attack-pattern--36675cd3-fe00-454c-8516-aebecacbe9d9+mitre_capec_vertex_collection/attack-pattern--b63b2869-11e6-4849-8ddf-ae2557bf554b` = 3916b361-59b6-5697-ba1a-020ddef6cf3b
    def test_05_checkT1162_relationships_ids(self):
        query = """
            FOR doc IN UNION(
                (FOR d IN mitre_attack_enterprise_edge_collection RETURN d),
                (FOR d IN mitre_attack_ics_edge_collection RETURN d),
                (FOR d IN mitre_attack_mobile_edge_collection RETURN d)
            )
              FILTER doc.relationship_type == "relies-on"
              AND doc.id == "relationship--3916b361-59b6-5697-ba1a-020ddef6cf3b"
              AND doc._is_ref == false
              RETURN doc.id
        """
        result_count = self.run_query(query)
        expected_ids = []
        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

# no updates to the objects should have happened yet

    def test_06_check_no_updates(self):
        query = """
            RETURN LENGTH(
              FOR doc IN UNION(
                (FOR d IN mitre_attack_enterprise_edge_collection RETURN d),
                (FOR d IN mitre_attack_ics_edge_collection RETURN d),
                (FOR d IN mitre_attack_mobile_edge_collection RETURN d)
                )
                FILTER doc._is_latest == false
                AND doc._arango_cti_processor_note == "attack-capec"
                AND doc._is_ref == false
                RETURN doc
            )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [0], f"Expected 0 documents, but found {result_count}.")

    def test_07_check_object_description_properties(self):
        query = """
            FOR doc IN UNION(
                (FOR d IN mitre_attack_enterprise_edge_collection RETURN d),
                (FOR d IN mitre_attack_ics_edge_collection RETURN d),
                (FOR d IN mitre_attack_mobile_edge_collection RETURN d)
                )
                FILTER doc._arango_cti_processor_note == "attack-capec"
                AND doc.id == "relationship--443510b1-b5e1-5dd0-b36c-c98cb32235f8"
                AND doc._is_ref == false
                RETURN doc.description
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = []

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()
