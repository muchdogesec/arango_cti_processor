import itertools
import uuid

from arango_cti_processor import config
from .base_manager import RelationType, STIXRelationManager
import requests


class D3fendAttack(
    STIXRelationManager, relationship_note="d3fend-attack", register=True
):
    priority = 8
    edge_collection = "d3fend_edge_collection"
    vertex_collection = "d3fend_vertex_collection"
    MAPPING_URL = (
        "https://d3fend.mitre.org/ontologies/d3fend/{}/d3fend-full-mappings.json"
    )

    secondary_collection = "mitre_attack_enterprise_vertex_collection"
    required_collections = [edge_collection, vertex_collection, secondary_collection]

    source_name = "attack-pattern"
    type_filter = ["attack-pattern"]

    def __init__(self, processor, *args, version="", secondary_version=None, ignore_embedded_relationships=True, **kwargs):
        if not version:
            raise ValueError(f"version is required for `{self.relationship_note}` relation manager")
        super().__init__(processor, *args, version=version, secondary_version=secondary_version, ignore_embedded_relationships=ignore_embedded_relationships, **kwargs)

    def get_objects_from_db(self, **kwargs):
        binds = {
            "@vertex_collection": self.collection,
        }
        version_filter = "FILTER doc._is_latest == TRUE"
        if self.version:
            version_filter = "FILTER doc._stix2arango_note == @version_note"
            binds.update(
                version_note="version=" + self.version.replace(".", "_").strip("v")
            )

        query = """
FOR doc IN @@vertex_collection
FILTER doc.type == "indicator"
#VERSION
RETURN [doc.external_references[0].external_id, KEEP(doc, "created", "id", "modified", "_id", "name", "external_references")]
        """.replace(
            "#VERSION", version_filter
        )
        return dict(self.arango.execute_raw_query(query, bind_vars=binds))

    def retrieve_remote_date(self):
        url = self.MAPPING_URL.format(self.version)
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data["results"]["bindings"]

    @staticmethod
    def parse_from_uri(uri: str) -> str:
        return uri.split("#")[-1]

    def get_object_chunks(self, **kwargs):
        remote_data = self.retrieve_remote_date()
        self.primary_data = self.get_objects_from_db()
        if not self.primary_data:
            raise ValueError(f"no d3fend objects found for version `{self.version}`")
        self.secondary_data = self.get_secondary_objects(remote_data)
        return [remote_data]

    def relate_single(self, object):
        artifact_id = self.parse_from_uri(object["off_artifact"]["value"])
        artifact_obj = self.primary_data["d3f:" + artifact_id]
        off_tech_id = object["off_tech_id"]["value"]
        off_tech_obj = self.secondary_data[off_tech_id]
        rel_type = self.parse_from_uri(object["off_artifact_rel"]["value"])
        tech_name = self.parse_from_uri(object["off_tech_label"]["value"])
        rel = self.create_relationship(
            off_tech_obj,
            artifact_obj["id"],
            relationship_type=rel_type,
            description=f"{tech_name} ({off_tech_id}) {rel_type} {artifact_obj['name']}",
            external_references=[
                off_tech_obj["external_references"][0],
                artifact_obj["external_references"][0],
            ],
        )
        rel['_to'] = artifact_obj['_id']
        return [rel]

    def get_secondary_objects(self, remote_data):
        external_ids = set()
        for item in remote_data:
            external_ids.add(item["off_tech_id"]["value"])

        query = """
FOR doc IN @@vertex_collection
FILTER doc.external_references[0].external_id IN @external_ids AND doc._is_latest == TRUE
LET ext_id = doc.external_references[0].external_id
RETURN MERGE({ext_id}, KEEP(doc, "id", "_id", "external_references", "created", "modified"))
        """
        objects = self.arango.execute_raw_query(
            query,
            bind_vars={
                "@vertex_collection": self.secondary_collection,
                "external_ids": list(external_ids),
            },
        )
        ext_id_map = {obj["ext_id"]: obj for obj in objects}
        return ext_id_map
