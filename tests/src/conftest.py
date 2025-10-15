import datetime
import json
from pathlib import Path
import time
from typing import Any, Generator
from unittest.mock import patch
import pytest
from arango_cti_processor import config
from stix2arango.stix2arango.stix2arango import Stix2Arango
from stix2arango.services import ArangoDBService

# from arango_cti_processor.tools.utils import create_indexes


@pytest.fixture(scope='session')
def upload_all():
    base_file_path = Path('tests/files')
    data = [
        ('mitre_cwe', '1.9', 'cwe-objects.json'),
        ('mitre_capec', '3.7', 'capec_v3_7.json'),
        ('mitre_capec', '3.9', 'capec_v3_9.json'),
        ('mitre_attack_enterprise', '17.1', 'attack-enterprise-objects.json'),
    ]
    for collection, version, path in data:
        path = base_file_path/path
        s2a = Stix2Arango(
            "test_actip",
            collection,
            file=str(path),
            create_db=True,
            create_collection=True,
            host_url=config.ARANGODB_HOST_URL,
            username=config.ARANGODB_USERNAME,
            password=config.ARANGODB_PASSWORD,
            skip_default_indexes=False,
            bundle_id='-'.join([collection, version]),
            stix2arango_note=f"version="+version.replace('.', '_'),
        )
        s2a.run()
    yield s2a

@pytest.fixture(scope="session")
def session_processor(upload_all):
    return upload_all.arango
