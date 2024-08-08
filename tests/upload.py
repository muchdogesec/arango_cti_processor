import os
from dotenv import load_dotenv
from stix2arango.stix2arango import Stix2Arango
from arango import ArangoClient


# Load environment variables
load_dotenv()

ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD")
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL")

def delete_database(client: ArangoClient, db_name):
    sys_db = client.db('_system', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)
    if sys_db.has_database(db_name):
        sys_db.delete_database(db_name)
        print(f'=====Deleted database {db_name}======')
    else:
        print(f'======Database {db_name} does not exist, skipping.======')

def as_arango2stix_db(db_name):
    if db_name.endswith('_database'):
        return '_'.join(db_name.split('_')[:-1])
    return db_name

def make_uploads(uploads: list[tuple[str, str]], delete_db=False, database="arango_cti_processor_standard_tests", **kwargs):
    database = as_arango2stix_db(database)
    if delete_db:
        client = ArangoClient(hosts=ARANGODB_HOST_URL)
        delete_database(client, database+'_database')
    for collection, file in uploads:
        Stix2Arango(database=database, collection=collection, file=file, **kwargs).run()
    print('======Test bundles uploaded successfully======')
    print("==============================================\n"*10)
    print('======Test bundles uploaded successfully======')
    
