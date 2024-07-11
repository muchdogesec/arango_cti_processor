import os
import subprocess
from arango import ArangoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

ARANGO_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGO_PASSWORD = os.getenv("ARANGODB_PASSWORD")
ARANGO_HOST = os.getenv("ARANGODB_HOST", "localhost")
ARANGO_PORT = os.getenv("ARANGODB_PORT", "8529")

client = ArangoClient(hosts=f"http://{ARANGO_HOST}:{ARANGO_PORT}")

# Run the import script
subprocess.run([
    "python3", "arango_cti_processor.py",
    "--database", "arango_cti_processor_standard_tests_database",
    "--relationship", "capec-attack",
    "--stix2arango_note", "test01",
    "--ignore_embedded_relationships", "false"
], check=True)

print('Script executed successfully.')

# test 1 Should return 6 objects, the newest version, and 5 old ones.

def test_01_updated_capec158():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_vertex_collection
          FILTER doc.id == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
          RETURN [doc]
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [6], f"Expected 6 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_01_updated_CAPEC158()

# test 2 Should return 25 results. oldest version (1.0) of CAPEC158 had 4 ATT&CK references, old version 1.1 had 5 ATT&CK references, old version 1.2 had 6, 1.3 had 4, 1.4 had 6

def test_02_updated_capec158_old_relationships():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
          FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
          AND doc._arango_cti_processor_note == "capec-attack"
          AND doc._is_latest == false
          RETURN [doc]
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [25], f"Expected 25 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_02_updated_capec158_old_relationships()

# test 3 Should return 0 results because the new object has 0 ATT&CK references

def test_03_updated_capec158_new_relationships():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
          FILTER doc.source_ref == "attack-pattern--897a5506-45bb-4f6f-96e7-55f4c0b9021a"
          AND doc._arango_cti_processor_note == "capec-attack"
          AND doc._is_latest == true
          RETURN [doc]
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [0], f"Expected 0 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_03_updated_capec158_new_relationships()