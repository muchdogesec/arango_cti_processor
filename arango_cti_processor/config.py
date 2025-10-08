import os
import logging
from dotenv import load_dotenv
from uuid import UUID

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",  # noqa D100 E501
    datefmt="%Y-%m-%d - %H:%M:%S",
)
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL")
ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD")


namespace = UUID("2e51a631-99d8-52a5-95a6-8314d3f4fbf3")

DEFAULT_OBJECT_URL = [
    "https://github.com/muchdogesec/stix4doge/raw/main/objects/marking-definition/arango_cti_processor.json", # this is arango_cti_processor marking-definition
    "https://github.com/muchdogesec/stix4doge/raw/main/objects/identity/dogesec.json" # this is dogesec identity
]


EPSS_API_ENDPOINT = "https://api.first.org/data/v1/epss"

OBJECT_MARKING_REFS=[
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
]
IDENTITY_REF = "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"