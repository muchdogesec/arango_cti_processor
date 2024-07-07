import os
from arango import ArangoClient
from dotenv import load_dotenv

load_dotenv()

ARANGO_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGO_PASSWORD = os.getenv("ARANGODB_PASSWORD")
ARANGODB_DATABASE = os.getenv("ARANGODB_DATABASE")

client = ArangoClient(hosts=f"http://{os.getenv('ARANGODB_HOST', 'localhost')}:{os.getenv('ARANGODB_PORT')}")

# Connect to "cti_database" as root user
# Replace with your database credentials

db = client.db(
    ARANGODB_DATABASE,
    username=ARANGO_USERNAME,
    password=ARANGO_PASSWORD)

# List of collections to remove documents from
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

# Function to remove all documents from a collection
def remove_documents(collection_name):
    query = f'FOR doc IN {collection_name} REMOVE doc IN {collection_name}'
    db.aql.execute(query)

# Execute the removal for each collection
for collection in collections:
    remove_documents(collection)
    print(f'Removed documents from {collection}')

print('All specified collections have been cleared.')
