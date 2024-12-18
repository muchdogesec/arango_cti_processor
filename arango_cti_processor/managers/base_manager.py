

import itertools
import logging
from types import SimpleNamespace
import uuid

from tqdm import tqdm
from arango_cti_processor import config
from enum import IntEnum, StrEnum
from stix2arango.services.arangodb_service import ArangoDBService

from arango_cti_processor.tools.utils import generate_md5, get_embedded_refs


class RelationType(StrEnum):
    RELATE_SEQUENTIAL = "sequential"
    RELATE_PARALLEL = "parallel"


RELATION_MANAGERS: dict[str, 'type[STIXRelationManager]'] = {}

class STIXRelationManager:
    MIN_DATE_STR = "1970-01-01"

    def __init_subclass__(cls,/, relationship_note) -> None:
        cls.relationship_note = relationship_note
        RELATION_MANAGERS[relationship_note] = cls

    relation_type: RelationType = RelationType.RELATE_SEQUENTIAL
    vertex_collection : str = None
    edge_collection : str = None

    containing_collection : str = None
    relationship_note: str = 'stix-relation-manager'
    default_objects = []

    required_collections = []

    priority = 10 # used to determine order of running, for example cve_cwe must run before cve_capec, lower => run earlier

    def __init__(self, processor: ArangoDBService, *args, modified_min=None, created_min=None, ignore_embedded_relationships=True, **kwargs) -> None:
        self.arango = processor
        self.client = self.arango._client
        self.created_min = created_min or self.MIN_DATE_STR
        self.modified_min = modified_min or self.MIN_DATE_STR
        self.ignore_embedded_relationships = ignore_embedded_relationships

    @property
    def collection(self):
        return self.containing_collection or self.vertex_collection

    def get_objects(self, **kwargs):
        query = """
        FOR doc IN @@collection
        FILTER doc._is_latest
        RETURN doc
        """
        return self.arango.execute_raw_query(query, bind_vars={'@collection': self.collection})
    
    @classmethod
    def create_relationship(cls, source, target_ref, relationship_type, description, relationship_id=None, is_ref=False, external_references=None):
        if not relationship_id:
            relationship_id = "relationship--" + str(
                uuid.uuid5(
                    config.namespace,
                    f"{relationship_type}+{source['id']}+{target_ref}",
                )
            )
            
        retval = dict(
            id=relationship_id,
            type="relationship",
            created=source.get("created"),
            modified=source.get("modified"),
            relationship_type=relationship_type,
            source_ref=source.get("id"),
            target_ref=target_ref,
            created_by_ref=config.IDENTITY_REF,
            object_marking_refs=config.OBJECT_MARKING_REFS,
            description=description,
            _arango_cti_processor_note=cls.relationship_note,
            _from=source.get('_id'),
            _is_ref=is_ref,
        )
        if external_references:
            retval['external_references'] = external_references
        return retval
    
    def import_external_data(self, objects) -> dict[str, dict]:
        pass

    def upload_vertex_data(self, objects):
        logging.info("uploading %d vertices", len(objects))
        for obj in objects:
            obj['_arango_cti_processor_note'] = self.relationship_note
            obj['_record_md5_hash'] = generate_md5(obj)
            
        inserted_ids, existing_objects = self.arango.insert_several_objects_chunked(objects, self.vertex_collection)
        self.arango.update_is_latest_several_chunked(inserted_ids, self.vertex_collection, self.edge_collection)

    
    def upload_edge_data(self, objects: list[dict]):
        logging.info("uploading %d edges", len(objects))

        ref_ids = []
        for edge in objects:
            ref_ids.append(edge['target_ref'])
            ref_ids.append(edge['source_ref'])
        edge_id_map = self.get_edge_ids(ref_ids, self.collection)

        for edge in objects:
            edge.setdefault('_from', edge_id_map.get(edge['source_ref'], edge['source_ref']))
            edge.setdefault('_to', edge_id_map.get(edge['target_ref'], edge['target_ref']))
            edge['_record_md5_hash'] = generate_md5(edge)

        inserted_ids, existing_objects = self.arango.insert_several_objects_chunked(objects, self.edge_collection)
        self.arango.update_is_latest_several_chunked(inserted_ids, self.edge_collection, self.edge_collection)
        if not self.ignore_embedded_relationships:
            self.create_embedded_relationships(objects, self.vertex_collection, self.edge_collection)

    def create_embedded_relationships(self, objects, *collections):
        edge_ids = {}
        obj_targets_map = {}
        for edge in objects:
            obj_targets_map[edge['id']] = get_embedded_refs(edge)
        ref_ids = [target_ref for _, target_ref in itertools.chain(*obj_targets_map.values())] + list(obj_targets_map)

        for collection in collections:
            edge_ids.update(self.get_edge_ids(ref_ids, collection))

        embedded_relationships = []
        for obj in objects:
            for ref, target_id in obj_targets_map.get(obj['id'], []):
                _from, _to = edge_ids.get(obj['id']), edge_ids.get(target_id)
                if not (_to and _from):
                    continue
                rel = self.create_relationship(obj, target_ref=target_id, relationship_type=ref, is_ref=True, description=None)
                rel['_to'] = _to
                rel['_from'] = _from
                rel['_record_md5_hash'] = generate_md5(rel)
                embedded_relationships.append(rel)

        inserted_ids, existing_objects = self.arango.insert_several_objects_chunked(embedded_relationships, self.edge_collection)
        self.arango.update_is_latest_several_chunked(inserted_ids, self.edge_collection, self.edge_collection)
        return embedded_relationships

    def get_edge_ids(self, object_ids, collection=None) -> dict[str, str]:
        """
        Given object IDs, this returns the `doc._id` the latest object with same id
        """
        if not collection:
            collection = self.collection
        query = """
        FOR doc IN @@collection
        FILTER doc.id IN @object_ids
        SORT doc.modified ASC
        RETURN [doc.id, doc._id]
        """
        result = self.arango.execute_raw_query(query, bind_vars={'@collection': collection, 'object_ids': list(set(object_ids))})
        return dict(result)
        
    def relate_single(self, object):
        raise NotImplementedError('must be subclassed')
    
    def relate_multiple(self, objects):
        raise NotImplementedError('must be subclassed')
    
    def _filter_cve_ids(self, objects: list[dict]):
        logging.info("filtering with --cve_ids")
        if not self.cve_ids:
            return objects
        retval = []
        for i, obj in enumerate(objects):
            if obj['name'].upper() in self.cve_ids:
                retval.append(obj)
        logging.info("filter --cve_ids: %d objects", len(retval))
        return retval
    

    
    def process(self, **kwargs):
        logging.info("getting objects")
        objects = self.get_objects(**kwargs)
        logging.info("got %d objects", len(objects))
        uploads = []
        match self.relation_type:
            case RelationType.RELATE_SEQUENTIAL:
                for obj in tqdm(objects, desc=f'{self.relationship_note} - {self.relation_type}'):
                    uploads.extend(self.relate_single(obj))
            case RelationType.RELATE_PARALLEL:
                uploads.extend(self.relate_multiple(objects))
        
        edges, vertices = [], []
        for obj in uploads:
            if obj['type'] == 'relationship':
                edges.append(obj)
            else:
                vertices.append(obj)

        self.upload_vertex_data(vertices)
        self.upload_edge_data(edges)
 
