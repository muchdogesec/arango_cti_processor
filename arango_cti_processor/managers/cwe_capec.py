import itertools
import uuid

from arango_cti_processor import config
from .base_manager import RelationType, STIXRelationManager


class CweCapec(STIXRelationManager, relationship_note="cwe-capec"):
    priority = 9
    edge_collection = "mitre_cwe_edge_collection"
    vertex_collection = "mitre_cwe_vertex_collection"

    secondary_collection = "mitre_capec_vertex_collection"
    required_collections = [edge_collection, vertex_collection, secondary_collection]

    source_name = "capec"
    type_filter = ["weakness"]

    def get_objects_from_db(self, **kwargs):
        binds = {
            "@vertex_collection": self.collection,
            "types": self.type_filter,
            "source_name": self.source_name,
        }
        version_filter = "FILTER doc._is_latest == TRUE"
        if self.version:
            version_filter = "FILTER doc._stix2arango_note == @version_note"
            binds.update(
                version_note="version=" + self.version.replace(".", "_").strip("v")
            )

        query = """
FOR doc IN @@vertex_collection
FILTER doc.type IN @types
#VERSION
LET ref_ids = (FOR d IN doc.external_references FILTER d.source_name == @source_name RETURN d.external_id)
FILTER LENGTH(ref_ids) > 0
LET ext_id = doc.external_references[0].external_id
LET name = CONCAT(ext_id, " (", doc.name, ")")
RETURN MERGE({name, ref_ids, ext_id}, KEEP(doc, "created", "id", "modified", "_id" ))
        """.replace(
            "#VERSION", version_filter
        )
        return self.arango.execute_raw_query(query, bind_vars=binds)

    def get_external_references(self, cwe_id: str, capec_id: str):
        return [
            dict(
                source_name="cwe",
                external_id=cwe_id,
                url=f"http://cwe.mitre.org/data/definitions/{cwe_id.split('-', 1)[-1]}.html",
            ),
            dict(
                source_name="capec",
                external_id=capec_id,
                url=f"https://capec.mitre.org/data/definitions/{capec_id.split('-', 1)[-1]}.html",
            ),
        ]

    def get_secondary_objects(self, external_ids):
        query = """
FOR doc IN @@vertex_collection
FILTER doc.external_references[0].external_id IN @external_ids AND doc._is_latest == TRUE
LET ext_id = doc.external_references[0].external_id
LET name = CONCAT(ext_id, " (", doc.name, ")")
RETURN MERGE({name, ext_id}, KEEP(doc, "created", "id", "modified", "_id" ))
        """
        objects = self.arango.execute_raw_query(
            query,
            bind_vars={
                "@vertex_collection": self.secondary_collection,
                "external_ids": external_ids,
            },
        )
        obj_map: dict[str, list[dict]] = {}
        for obj in objects:
            ref_objects = obj_map.setdefault(obj["ext_id"], [])
            ref_objects.append(obj)
        return obj_map

    def relate_single(self, obj):
        retval = []
        secondary_objects = self.secondary_objects
        for ref_id in obj["ref_ids"]:
            for ref_obj in secondary_objects.get(ref_id, []):
                relationship_obj = self.get_rel_object(obj, ref_obj)
                relationship_obj["_to"] = ref_obj["_id"]
                relationship_obj["id"] = self.get_rel_id(relationship_obj)
                retval.append(relationship_obj)
        return retval

    def get_object_chunks(self):
        objects = self.get_objects_from_db()
        external_ids = list(itertools.chain(*[obj["ref_ids"] for obj in objects]))
        self.secondary_objects = self.get_secondary_objects(external_ids)
        return objects and [objects]

    def get_rel_object(self, obj, ref_obj):
        return self.create_relationship(
            obj,
            ref_obj["id"],
            relationship_type="related-to",
            description=f"{obj['name']} is exploited using {ref_obj['name']}",
            external_references=self.get_external_references(
                obj["ext_id"], ref_obj["ext_id"]
            ),
        )

    def get_rel_id(self, rel_obj):
        return "relationship--" + str(
            uuid.uuid5(
                config.namespace,
                f"{rel_obj['relationship_type']}+{rel_obj['_from'].split('+')[0]}+{rel_obj['_to'].split('+')[0]}",
            )
        )
