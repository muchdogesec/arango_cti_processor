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
    "--relationship", "capec-cwe",
    "--stix2arango_note", "test02",
    "--ignore_embedded_relationships", "false"
], check=True)

print('Script executed successfully.')

def test_01_auto_imported_objects():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
      FOR doc IN mitre_capec_vertex_collection
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

# test 2 checks all objects generated correctly

def test_02_arango_cti_processor_note():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
      FILTER doc._arango_cti_processor_note == "capec-cwe"
        RETURN [doc]
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [1212], f"Expected 1212 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_02_arango_cti_processor_note()

# test 3 checks the corret number of objects are generated, and that they are assigned the correct properties by the script

def test_03_correct_object_properties():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
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
        RETURN [doc]
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [1212], f"Expected 1212 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_03_correct_object_properties()

# test 4 To check objects are created as expected, you can pick a CAPEC object with CWE references and then check all the SROs for CWE are generated for it, as follows...
# e.g. [CAPEC-112](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1.json) which has links to: CWE-330 (weakness--e72563af-bb4e-59d9-926c-95344c1ef7e0), CWE-326 (weakness--611422c2-1201-50dc-8c94-0ddf62565555), CWE-521 (weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5)

def test_04_correct_relationship_capec112():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        FOR doc IN mitre_capec_edge_collection
          FILTER doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-cwe"
          AND doc.source_ref == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
          RETURN doc.target_ref
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "weakness--e72563af-bb4e-59d9-926c-95344c1ef7e0",
        "weakness--611422c2-1201-50dc-8c94-0ddf62565555",
        "weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5"
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_04_correct_relationship_capec112()

# test 5 is extension of test 4 to check id generation:
# object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1+mitre_cwe_vertex_collection/weakness--e72563af-bb4e-59d9-926c-95344c1ef7e0` = d931a94d-039a-57b7-a089-21d80bc3b1de
# object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1+mitre_cwe_vertex_collection/weakness--611422c2-1201-50dc-8c94-0ddf62565555` = c98b705d-747f-5b5b-870a-0fae14bcfd14
# object id `2e51a631-99d8-52a5-95a6-8314d3f4fbf3` `technique+mitre_capec_vertex_collection/attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1+mitre_cwe_vertex_collection/weakness--e7a435fe-cc39-5a78-a362-eecdc61c80e5` = 8eaf77d7-9bd5-5ccd-9a46-b2c002d4b47b

def test_05_correct_relationship_capec112_ids():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        FOR doc IN mitre_capec_edge_collection
          FILTER doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-cwe"
          AND doc.source_ref == "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
          RETURN doc.id
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "relationship--d931a94d-039a-57b7-a089-21d80bc3b1de",
        "relationship--c98b705d-747f-5b5b-870a-0fae14bcfd14",
        "relationship--8eaf77d7-9bd5-5ccd-9a46-b2c002d4b47b"
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_05_correct_relationship_capec112_ids()