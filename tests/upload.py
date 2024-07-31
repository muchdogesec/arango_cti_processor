import os
from dotenv import load_dotenv
from stix2arango.stix2arango import Stix2Arango

from .delete_all_databases import delete_database

# Load environment variables
load_dotenv()

ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD")
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL")


def as_arango2stix_db(db_name):
    if db_name.endswith('_database'):
        return db_name
    return db_name + '_database'

def make_uploads(uploads: list[tuple[str, str]], delete_db=False, database="arango_cti_processor_standard_tests", **kwargs):
    if delete_db:
        delete_database(as_arango2stix_db(database))
    for collection, file in uploads:
        Stix2Arango(database=database, collection=collection, file=file, **kwargs).run()
