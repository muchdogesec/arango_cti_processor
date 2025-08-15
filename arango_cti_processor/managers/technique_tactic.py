import itertools
import uuid

from arango_cti_processor import config
from arango_cti_processor.tools.utils import import_default_objects
from .base_manager import RelationType, STIXRelationManager
from stix2arango.services import ArangoDBService
from arango_cti_processor import config


class TechniqueTactic(STIXRelationManager, relationship_note="technique-tactic", register=False):
    relation_type = RelationType.RELATE_SEQUENTIAL
    priority = 10
    stix2arango_note = None

    def __init__(
        self,
        processor,
        version,
        collection,
    ):
        super().__init__(
            processor
        )
        if not isinstance(version, str):
            raise ValueError(f"version must be of type string, got: {version=}")
        self.version_note = "version=" + version.replace(".", "_").strip("v")
        self.edge_collection = collection + '_edge_collection'
        self.vertex_collection = collection + '_vertex_collection'
        self.required_collections = [self.edge_collection, self.vertex_collection]

    def get_objects(self, **kwargs):
        query = """
FOR doc IN @@vertex_collection
FILTER doc.type IN ['attack-pattern', 'x-mitre-tactic']
FILTER doc._stix2arango_note == @version_note
RETURN KEEP(doc, "_id", "_key", "id", "kill_chain_phases", "external_references", "x_mitre_shortname", "type", "name", "created", "modified")
        """
        docs = self.arango.execute_raw_query(
            query,
            bind_vars={
                "@vertex_collection": self.collection,
                "version_note": self.version_note,
            },
        )
        self.tactics = {}
        techniques = []
        for d in docs:
            d.update(attack_id=d['external_references'][0]['external_id'])
            if d["type"] == "x-mitre-tactic":
                self.tactics[d["x_mitre_shortname"]] = d
                continue
            techniques.append(d)
        return techniques

    def relate_single(self, obj):
        relationships: list[dict] = []
        for tactic in self.get_phases(obj.get('kill_chain_phases', [])):
            relationships.append(
                self.create_relationship(
                    obj,
                    tactic["id"],
                    relationship_type="tactic",
                    description=f"{obj['attack_id']} ({obj['name']}) is tactic {tactic['attack_id']} ({tactic['name']})",
                    external_references=(obj['external_references'][0], tactic['external_references'][0]),
                )
            )
            relationships[-1].update(_to=tactic['_id'])
            if self.stix2arango_note:
                relationships[-1].update(_stix2arango_note=self.stix2arango_note)
        return relationships

    def get_phases(self, kill_phases: list[dict[str, str]]):
        tactics = []
        for phase in kill_phases:
            phase_name = phase["phase_name"]
            if phase_name in self.tactics:
                tactics.append(self.tactics[phase_name])
        return tactics

    @classmethod
    def make_relations(cls, collection, version, database='ctibutler', stix2arango_note=''):
        processor = ArangoDBService(
            database,
            [],
            [],
            host_url=config.ARANGODB_HOST_URL,
            username=config.ARANGODB_USERNAME,
            password=config.ARANGODB_PASSWORD,
        )
        relation_manager = cls(processor, version=version, collection=collection)
        relation_manager.stix2arango_note = stix2arango_note
        import_default_objects(processor, cls.default_objects, relation_manager.required_collections)
        relation_manager.process()