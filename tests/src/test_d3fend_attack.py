import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from arango_cti_processor.managers.d3fend_attack import D3fendAttack


# Sample mock data for D3FEND remote mapping
@pytest.fixture
def raw_remote_data():
    return json.loads(Path("tests/files/d3fend-mock-remote-data.json").read_text())


@pytest.fixture
def remote_data(raw_remote_data):
    return raw_remote_data["results"]["bindings"]


def test_init_requires_version(session_processor):
    """Test that D3fendAttack requires a version parameter."""
    with pytest.raises(ValueError, match="version is required"):
        D3fendAttack(session_processor)


def test_init_with_version(session_processor):
    """Test that D3fendAttack initializes with a version."""
    manager = D3fendAttack(session_processor, version="1.3.0")
    assert manager.version == "1.3.0"
    assert manager.relationship_note == "d3fend-attack"


def test_init_version_normalization(session_processor):
    """Test that version normalization works correctly."""
    manager = D3fendAttack(session_processor, version="v1_3_0")
    assert manager.version == "1.3.0"


def test_parse_from_uri():
    """Test the static method parse_from_uri."""
    uri = "http://d3fend.mitre.org/ontologies/d3fend.owl#AccessToken"
    result = D3fendAttack.parse_from_uri(uri)
    assert result == "AccessToken"

    uri2 = "http://d3fend.mitre.org/ontologies/d3fend.owl#SessionCookie"
    result2 = D3fendAttack.parse_from_uri(uri2)
    assert result2 == "SessionCookie"


def test_get_objects_from_db(session_processor):
    """Test retrieving D3FEND artifacts from the database."""
    manager = D3fendAttack(session_processor, version="1.3.0")
    objects = manager.get_objects_from_db()

    # Should return a dictionary keyed by external_id
    assert isinstance(objects, dict)
    assert len(objects) > 0

    # Check that keys are d3f: prefixed
    for key in objects.keys():
        assert key.startswith("d3f:")

    # Check structure of returned objects
    for obj in objects.values():
        assert "id" in obj
        assert "created" in obj
        assert "modified" in obj
        assert "_id" in obj
        assert "name" in obj
        assert "external_references" in obj


@pytest.fixture
def d3fend_manager(session_processor, remote_data):
    """Fixture to create a D3fendAttack manager with mocked data."""
    manager = D3fendAttack(session_processor, version="1.3.0")
    manager.primary_data = manager.get_objects_from_db()
    manager.secondary_data = manager.get_secondary_objects(remote_data)
    return manager


def test_get_secondary_objects(session_processor, remote_data):
    """Test retrieving ATT&CK techniques from the database."""
    manager = D3fendAttack(session_processor, version="1.3.0")

    # Mock some remote data to extract technique IDs
    secondary_objects = manager.get_secondary_objects(remote_data)

    assert "T1542.002" in secondary_objects
    assert secondary_objects["T1211"] == {
        "ext_id": "T1211",
        "id": "attack-pattern--fe926152-f431-4baf-956c-4ad3cb0bf23b",
        "modified": "2025-04-15T19:59:24.778Z",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1211",
                "external_id": "T1211",
            },
            {
                "source_name": "Salesforce zero-day in facebook phishing attack",
                "description": "Bill Toulas. (2023, August 2). Hackers exploited Salesforce zero-day in Facebook phishing attack. Retrieved September 18, 2023.",
                "url": "https://www.bleepingcomputer.com/news/security/hackers-exploited-salesforce-zero-day-in-facebook-phishing-attack/",
            },
            {
                "source_name": "Bypassing CloudTrail in AWS Service Catalog",
                "description": "Nick Frichette. (2023, March 20). Bypassing CloudTrail in AWS Service Catalog, and Other Logging Research. Retrieved September 18, 2023.",
                "url": "https://securitylabs.datadoghq.com/articles/bypass-cloudtrail-aws-service-catalog-and-other/",
            },
            {
                "source_name": "GhostToken GCP flaw",
                "description": "Sergiu Gatlan. (2023, April 21). GhostToken GCP flaw let attackers backdoor Google accounts. Retrieved September 18, 2023.",
                "url": "https://www.bleepingcomputer.com/news/security/ghosttoken-gcp-flaw-let-attackers-backdoor-google-accounts/",
            },
        ],
        "created": "2018-04-18T17:59:24.739Z",
        "_id": "mitre_attack_enterprise_vertex_collection/attack-pattern--fe926152-f431-4baf-956c-4ad3cb0bf23b+2025-10-07T11:06:12.949358Z",
    }


@patch("arango_cti_processor.managers.d3fend_attack.requests.get")
def test_retrieve_remote_date(
    mock_get, session_processor, raw_remote_data, remote_data
):
    """Test fetching remote D3FEND mapping data."""
    # Mock the response
    mock_response = MagicMock()
    mock_response.json.return_value = raw_remote_data
    mock_get.return_value = mock_response

    manager = D3fendAttack(session_processor, version="1.3.0")
    data = manager.retrieve_remote_data()

    assert data == remote_data
    mock_get.assert_called_once_with(
        "https://d3fend.mitre.org/ontologies/d3fend/1.3.0/d3fend-full-mappings.json"
    )


@patch("arango_cti_processor.managers.d3fend_attack.requests.get")
def test_get_object_chunks(mock_get, session_processor, raw_remote_data, remote_data):
    """Test get_object_chunks fetches and prepares data correctly."""
    # Mock the remote data
    mock_response = MagicMock()
    mock_response.json.return_value = raw_remote_data
    mock_get.return_value = mock_response

    manager = D3fendAttack(session_processor, version="1.3.0")
    chunks = list(manager.get_object_chunks())

    assert len(chunks) == 1
    assert chunks[0] == remote_data

    # Check that primary_data and secondary_data are populated
    assert hasattr(manager, "primary_data")
    assert hasattr(manager, "secondary_data")
    assert isinstance(manager.primary_data, dict)
    assert isinstance(manager.secondary_data, dict)


@patch("arango_cti_processor.managers.d3fend_attack.requests.get")
def test_get_object_chunks_no_d3fend_objects(
    mock_get, session_processor, raw_remote_data
):
    """Test that ValueError is raised when no D3FEND objects are found."""
    # Mock the remote data
    mock_response = MagicMock()
    mock_response.json.return_value = raw_remote_data
    mock_get.return_value = mock_response

    # Use a non-existent version
    manager = D3fendAttack(session_processor, version="99.99.99")

    with pytest.raises(ValueError, match="no d3fend objects found for version"):
        list(manager.get_object_chunks())


@patch("arango_cti_processor.managers.d3fend_attack.requests.get")
def test_relate_single(mock_get, session_processor, raw_remote_data, remote_data):
    """Test creating a relationship between ATT&CK technique and D3FEND artifact."""
    # Mock the remote data
    mock_response = MagicMock()
    mock_response.json.return_value = raw_remote_data
    mock_get.return_value = mock_response

    manager = D3fendAttack(session_processor, version="1.3.0")

    # Set up the data
    manager.primary_data = manager.get_objects_from_db()
    manager.secondary_data = manager.get_secondary_objects(remote_data)

    relationships = manager.relate_single(
        remote_data[0]
    )  # Use the first mapping object

    assert len(relationships) == 1
    rel = relationships[0]
    assert rel == {
        "id": "relationship--584de2ab-a2b4-57ef-81b2-7c813e6775a2",
        "type": "relationship",
        "created": "2020-02-11T19:01:56.887Z",
        "modified": "2025-04-15T19:59:21.746Z",
        "relationship_type": "modifies",
        "source_ref": "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84",
        "target_ref": "indicator--5a0e32f1-e049-58cc-bf2a-ecd0faca0210",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
        ],
        "description": "Modify Authentication Process (T1556) modifies Authentication Service",
        "_arango_cti_processor_note": "d3fend-attack",
        "_from": "mitre_attack_enterprise_vertex_collection/attack-pattern--f4c1826f-a322-41cd-9557-562100848c84+2025-10-07T11:06:12.949399Z",
        "_is_ref": False,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/techniques/T1556",
                "external_id": "T1556",
            },
            {
                "source_name": "mitre-d3fend",
                "url": "https://d3fend.mitre.org/dao/artifact/d3f:AuthenticationService",
                "external_id": "d3f:AuthenticationService",
            },
        ],
        "_to": manager.primary_data["d3f:AuthenticationService"]["_id"],
    }
