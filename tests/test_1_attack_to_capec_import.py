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

print('Import script executed successfully.')

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
        "marking-definition--af79980e-cce7-5a67-becb-82ad5a68e850",
        "identity--af79980e-cce7-5a67-becb-82ad5a68e850"
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_01_auto_imported_objects()

def test_02_arango_cti_processor_note():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
      FILTER doc._arango_cti_processor_note == "capec-attack"
        RETURN [doc]
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [338], f"Expected 338 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_02_arango_cti_processor_note()

def test_03_correct_object_properties():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
    RETURN COUNT(
      FOR doc IN mitre_capec_edge_collection
        FILTER doc._is_latest == true
        AND doc.type == "relationship"
        AND doc.relationship_type == "technique"
        AND doc.created_by_ref == "identity--af79980e-cce7-5a67-becb-82ad5a68e850"
        AND doc.object_marking_refs == [
          "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          "marking-definition--af79980e-cce7-5a67-becb-82ad5a68e850"
        ]
        AND doc._arango_cti_processor_note == "capec-attack"
        RETURN [doc]
    )
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    assert result_count == [338], f"Expected 338 documents, but found {result_count}."
    print(f"Test passed. Found {result_count[0]} documents with the specified criteria.")

test_03_correct_object_properties()

# test 4 checks [CAPEC-695](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001.json) -> T1195.001

def test_04_correct_relationship_capec695():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        FOR doc IN mitre_capec_edge_collection
          FILTER doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          AND doc.relationship_type == "technique"
          AND doc.created_by_ref == "identity--af79980e-cce7-5a67-becb-82ad5a68e850"
          AND doc.source_ref == "attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001"
          AND doc.object_marking_refs == [
            "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "marking-definition--af79980e-cce7-5a67-becb-82ad5a68e850"
          ]
          RETURN doc.target_ref
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "attack-pattern--191cc6af-1bb2-4344-ab5f-28e496638720"
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")

test_04_correct_relationship_capec695()

# test 5 namespace: `af79980e-cce7-5a67-becb-82ad5a68e850` value: `technique+mitre_capec_vertex_collection/attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001+mitre_attack_enterprise_vertex_collection/attack-pattern--191cc6af-1bb2-4344-ab5f-28e496638720`

def test_05_relationship_id_generation():
    db = client.db('arango_cti_processor_standard_tests_database', username=ARANGO_USERNAME, password=ARANGO_PASSWORD)
    query = """
        FOR doc IN mitre_capec_edge_collection
          FILTER doc._is_latest == true
          AND doc._arango_cti_processor_note == "capec-attack"
          AND doc.relationship_type == "technique"
          AND doc.created_by_ref == "identity--af79980e-cce7-5a67-becb-82ad5a68e850"
          AND doc.source_ref == "attack-pattern--e3dd79e7-307b-42dd-9e22-d0345c0ec001"
          AND doc.object_marking_refs == [
            "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "marking-definition--af79980e-cce7-5a67-becb-82ad5a68e850"
          ]
          RETURN doc.id
    """
    cursor = db.aql.execute(query)
    result_count = [count for count in cursor]

    expected_ids = [
        "relationship--4d3a7c77-895d-5394-8f66-4b96ccdb9f8a"
    ]

    assert result_count == expected_ids, f"Expected {expected_ids}, but found {result_count}."
    print(f"Test passed. Found documents with the specified note: {result_count}")





