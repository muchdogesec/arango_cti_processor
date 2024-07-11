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
    "--relationship", "cwe-capec",
    "--stix2arango_note", "test03",
    "--ignore_embedded_relationships", "false"
], check=True)

print('Script executed successfully.')

# should still return 2 objects b/c these never update

def test_01_auto_imported_objects():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
      FOR doc IN mitre_cwe_vertex_collection
        FILTER doc._arango_cti_processor_note == "automatically imported object at script runtime"
        RETURN doc.id
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
        "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_01_auto_imported_objects()

# test 2 Should return 2 results, the new and the old object.

def test_02_cwe521_versions():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_cwe_vertex_collection
          FILTER doc.id == "weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5"
          RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [2], f"Expected 2 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_02_cwe521_versions()

# test 3 Should return 9 results, the old sro objects in 3.0.

def test_03_cwe521_old_rel_versions():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_cwe_edge_collection
          FILTER doc.source_ref == "weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5"
          AND doc._is_latest == false
          AND doc._arango_cti_processor_note == "cwe-capec"
          RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [9], f"Expected 9 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_03_cwe521_old_rel_versions()

# test 4 Should return 10 results, inc. the newly added object

def test_04_cwe521_new_rel_versions():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_cwe_edge_collection
          FILTER doc.source_ref == "weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5"
          AND doc._is_latest == true
          AND doc._arango_cti_processor_note == "cwe-capec"
          RETURN doc
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [10], f"Expected 10 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_04_cwe521_new_rel_versions()