import itertools
import re
import uuid

from arango_cti_processor import config
from .base_manager import RelationType, STIXRelationManager
import requests


class D3fendAttack(
    STIXRelationManager, relationship_note="d3fend-knowledgebases", register=True
):
    priority = 8
    edge_collection = "d3fend_edge_collection"
    vertex_collection = "d3fend_vertex_collection"
    MAPPING_URL = "https://downloads.ctibutler.com/d3fend2stix-manual-output/d3fend-v{}-external-relationships.json"
    ATTACK_REGEX = re.compile(r"d3f:([TM][0-9]+.*$)")
    CWE_REGEX = re.compile(r"d3f:(CWE-[0-9]+.)")

    attack_collections = ["mitre_attack_enterprise_vertex_collection"]
    cwe_collection = "mitre_cwe_vertex_collection"

    required_collections = [
        edge_collection,
        vertex_collection,
        *attack_collections,
        cwe_collection,
    ]

    source_name = "attack-pattern"
    type_filter = ["attack-pattern"]

    def __init__(
        self,
        processor,
        *args,
        version="",
        secondary_version=None,
        ignore_embedded_relationships=True,
        **kwargs,
    ):
        if not version:
            raise ValueError(
                f"version is required for `{self.relationship_note}` relation manager"
            )
        version = version.replace("_", ".").strip("v")
        super().__init__(
            processor,
            *args,
            version=version,
            secondary_version=secondary_version,
            ignore_embedded_relationships=ignore_embedded_relationships,
            **kwargs,
        )

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

    def retrieve_remote_data(self):
        url = self.MAPPING_URL.format(self.version.replace(".", "_"))
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data

    @staticmethod
    def parse_from_uri(uri: str) -> str:
        return uri.split("#")[-1]

    def get_object_chunks(self, **kwargs):
        remote_data = self.retrieve_remote_data()
        self.primary_data = self.get_objects_from_db()
        if not self.primary_data:
            raise ValueError(f"no d3fend objects found for version `{self.version}`")
        self.secondary_data = self.get_secondary_objects(remote_data)
        return [remote_data]

    def relate_single(self, object):
        source_obj = self.primary_data.get(object["source"], self.secondary_data.get(object["source"]))
        target_obj = self.primary_data.get(object["target"], self.secondary_data.get(object["target"]))
        if not source_obj or not target_obj:
            return []
        

        rel = self.create_relationship(
            source_obj,
            target_obj["id"],
            relationship_type=object['type'][4:],
            description=object['description'],
            external_references=[
                source_obj["external_references"][0],
                target_obj["external_references"][0],
            ],
        )
        rel["_to"] = target_obj["_id"]
        return [rel]

    def get_secondary_objects(self, remote_data):
        cwe_ids = set()
        attack_ids = set()
        for d in remote_data:
            for k in ["source", "target"]:
                match = self.CWE_REGEX.match(d[k])
                if match:
                    cwe_ids.add(match.group(1))
                match = self.ATTACK_REGEX.match(d[k])
                if match:
                    attack_ids.add(match.group(1))

        query = """
FOR doc IN @@vertex_collection
FILTER doc.external_references[0].external_id IN @external_ids AND doc._is_latest == TRUE
LET ext_id = doc.external_references[0].external_id
RETURN MERGE({ext_id}, KEEP(doc, "id", "_id", "external_references", "created", "modified"))
        """
        ext_id_map = {}
        for collection in self.attack_collections + [self.cwe_collection]:
            objects = self.arango.execute_raw_query(
                query,
                bind_vars={
                    "@vertex_collection": collection,
                    "external_ids": list(cwe_ids.union(attack_ids)),
                },
            )
            ext_id_map.update({'d3f:'+obj["ext_id"]: obj for obj in objects})
        return ext_id_map
