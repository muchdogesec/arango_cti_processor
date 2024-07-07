import os
from arango import ArangoClient
from dotenv import load_dotenv

load_dotenv()

ARANGO_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGO_PASSWORD = os.getenv("ARANGODB_PASSWORD")
ARANGODB_DATABASE = os.getenv("ARANGODB_DATABASE")

client = ArangoClient(hosts=f"http://{os.getenv('ARANGODB_HOST', 'localhost')}:{os.getenv('ARANGODB_PORT')}")

# Connect to the database with your credentials
db = client.db(
    ARANGODB_DATABASE,
    username=ARANGO_USERNAME,
    password=ARANGO_PASSWORD)

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
    "sigma_rules_vertex_collection",
    "sigma_rules_edge_collection",
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
