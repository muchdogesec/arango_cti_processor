import os
from arango import ArangoClient
from dotenv import load_dotenv

load_dotenv()

ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL")
ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD")

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

# Database names
databases = [
    "arango_cti_processor_standard_tests_database"
]

# Function to delete a database
def delete_database(db_name):
    sys_db = client.db('_system', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)
    if sys_db.has_database(db_name):
        sys_db.delete_database(db_name)
        print(f'Deleted database {db_name}')
    else:
        print(f'Database {db_name} does not exist, skipping.')

# Execute the deletion for each database
for db_name in databases:
    delete_database(db_name)

print('All specified databases have been deleted.')
