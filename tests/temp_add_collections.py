import os
from arango import ArangoClient
from dotenv import load_dotenv

load_dotenv()

ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL")
ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD")
ARANGODB_DATABASE = "arango_cti_processor_standard_tests_database"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

# Connect to the database with your credentials
db = client.db(
    ARANGODB_DATABASE,
    username=ARANGODB_USERNAME,
    password=ARANGODB_PASSWORD)

# List of collections to create
collections = [
    "mitre_attack_enterprise_vertex_collection",
    "mitre_attack_enterprise_edge_collection",
    "mitre_attack_mobile_vertex_collection",
    "mitre_attack_mobile_edge_collection",
    "mitre_attack_ics_vertex_collection",
    "mitre_attack_ics_edge_collection",
    "mitre_capec_vertex_collection",
    "mitre_capec_edge_collection",
    "mitre_cwe_vertex_collection",
    "mitre_cwe_edge_collection",
    "sigmahq_rules_vertex_collection",
    "sigmahq_rules_edge_collection",
    "nvd_cve_vertex_collection",
    "nvd_cve_edge_collection",
    "nvd_cpe_vertex_collection",
    "nvd_cpe_edge_collection"
]

# Function to create a collection if it doesn't exist
def create_collection(collection_name):
    if not db.has_collection(collection_name):
        db.create_collection(collection_name)
        print(f'Created collection: {collection_name}')
    else:
        print(f'Collection {collection_name} already exists')

# Execute the creation for each collection
for collection in collections:
    create_collection(collection)

print('All specified collections have been created or already exist.')