import os
import json
import logging

import arango.exceptions

from . import config
from tqdm import tqdm
from stix2arango.services.arangodb_service import ArangoDBService
from jsonschema import validate
import itertools


from . import utils as processors
module_logger = logging.getLogger("data_ingestion_service")

class ArangoProcessor:
    AUTO_IMPORT_NOTE = "automatically imported object at script runtime"


    def __init__(self, database=None, **kwargs):
        self.relationships = kwargs.get("relationship")
        self.ignore_embedded_relationships = kwargs.get("ignore_embedded_relationships")
        self.stix2arango_note = kwargs.get("stix2arango_note", "")
        self.arango_database = database
        self.vertex_collections, self.edge_collections = self.get_collections_for_relationship()
        self.modified_min = kwargs.get("modified_min")
        self.created_min = kwargs.get("created_min")
        self.kwargs = {}

        self.arango = ArangoDBService(self.arango_database, self.vertex_collections, self.edge_collections, host_url=config.ARANGODB_HOST_URL, username=config.ARANGODB_USERNAME, password=config.ARANGODB_PASSWORD)
        self.validate_collections()

    def validate_collections(self):
        missing_collections = set()
        if len(self.vertex_collections) == 0:
            raise Exception(f"no collection selected")
        for collection in itertools.chain(self.edge_collections, self.vertex_collections):
            try:
                self.arango.db.collection(collection).info()
            except Exception as e:
                missing_collections.add(collection)
        if missing_collections:
            raise Exception(f"The following collections are missing. Please add them to continue. \n {missing_collections}")

    def get_collections_for_relationship(self):
        vertex_collections = []
        edge_collections = []
        
        for mode in self.relationships:
            if mode in config.MODE_COLLECTION_MAP:
                vertex_collections.extend(config.MODE_COLLECTION_MAP[mode])
            else:
                raise Exception(f"unknown mode `{mode}` passed in relationship")

        edge_collections = [col.replace('_vertex_', '_edge_') for col in vertex_collections]
        return vertex_collections, edge_collections

    def finalize_collections(self):

        relations_needs_to_run = []
        for key, value in processors.get_rel_func_mapping(self.relationships):
            logging.info(f"adding reltionships for {key}")
            for collection, func in value.items():
                relations_needs_to_run.append((key, collection, func))
            # relations_needs_to_run.extend([key]+list(value.items()))
        return relations_needs_to_run

    def default_objects(self):
        object_list = []
        for obj in config.DEFAULT_OBJECT_URL:
            data = json.loads(processors.load_file_from_url(obj))
            object_list.append(data)

        return object_list


    def process_bundle_into_graph(self, filename: str, core_collection_vertex: str, data=None, notes=None):
        if data.get("type", None) != "bundle":
            module_logger.error("Provided file is not a STIX bundle. Aborted")
            return False

        objects = []
        for obj in tqdm(data["objects"]):
            obj['_stix2arango_note'] = notes
            obj['_arango_cti_processor_note'] = notes
            obj['_record_md5_hash'] = processors.generate_md5(obj)
            objects.append(obj)
                
        module_logger.info(f"Inserting objects into database. Total objects: {len(objects)}")
        inserted_ids, existing = self.arango.insert_several_objects_chunked(objects, core_collection_vertex)
        self.arango.update_is_latest_several_chunked(inserted_ids, core_collection_vertex)

    def run(self):
        if not self.arango.missing_collection:
            return

        logging.info("Processing default objects now")
        for collect in self.vertex_collections:
            logging.info(f"Checking: {collect}")
            self.process_bundle_into_graph(
                filename="",
                data={
                    "type": "bundle",
                    "objects": self.default_objects()
                },
                notes=self.AUTO_IMPORT_NOTE,
                core_collection_vertex=collect
            )

        logging.info("Processing relationships now")
        for rel_note, vertex, func in self.finalize_collections():
            logging.info(f"Checking: {vertex}")
            bind_vars = {
                '@collection': vertex,
                'created_min': self.created_min,
                'modified_min': self.modified_min,
            }
            query = """
                FOR doc IN @@collection
                    FILTER doc._is_latest 
                        AND (NOT @created_min OR doc.created >= @created_min)
                        AND (NOT @modified_min OR doc.modified >= @modified_min) 
                        AND doc.x_mitre_deprecated != true
                        AND doc.revoked != true
                    RETURN doc
            """
            data = self.arango.execute_raw_query(query=query, bind_vars=bind_vars)
            inserted_data = self.map_relationships(
                data=data,
                relate_function=func,
                collection_vertex=vertex,
                collection_edge=vertex.replace("vertex", "edge"),
                notes=rel_note,
            )

            if "sigma" in vertex:
                processors.sigma_groups(self.arango)


    # def filter_objects_in_collection_using_custom_query(self, collection_name, custom_query):
    #     return self.arango.filter_objects_in_collection_using_custom_query(collection_name, custom_query)
    
    def filter_objects_in_collection_using_custom_query(
        self, collection_name: str = None, custom_query: str = "", **kwargs
    ):
        bind_vars = kwargs.pop('bind_vars', {})
        bind_vars['@collection'] = collection_name
        query = f"FOR doc IN @@collection\n"
        query += custom_query
        query += "\nRETURN doc"
        # print(query)
        try:
            cursor = self.arango.db.aql.execute(query, bind_vars=bind_vars, **kwargs)
            result = [doc for doc in cursor]
            return result
        except arango.exceptions.AQLQueryExecuteError:
            module_logger.error(f"AQL exception in the query: {query}")
            raise
    
    def filter_objects_in_list_collection_using_custom_query(self, *args, **kw):
        return self.arango.filter_objects_in_list_collection_using_custom_query(*args, **kw)
    
    def upsert_several_objects_chunked(self, objects, deprecate_obj, collection, rel_note, collection_vertex=""):
        logging.info("inserting %d items into %s", len(objects), collection)
        for obj in objects:
            if not obj.get('_stix2arango_note'):
                obj['_stix2arango_note'] = self.stix2arango_note
        inserted_ids, existing = self.arango.insert_several_objects_chunked(objects, collection, chunk_size=1000)
        logging.info("removed %d already existing object", len(existing))
        self.arango.update_is_latest_several_chunked(inserted_ids, collection_name=collection, chunk_size=2000)
        logging.info("deprecating old relations")
        deprecated = self.deprecate_old_relations_chunked(deprecate_obj, collection, rel_note)
        logging.info(f"deprecated {len(deprecated)} relationships")
        self.create_embedded_relationships([obj for obj in objects if obj['id'] in inserted_ids], collection, collection_vertex, rel_note)
        updated = self.arango.update_is_latest_for_embedded_refs([v[0] for v in deprecate_obj], collection)

        return []
    
    def upsert_several_vertices_chuncked(self, vertices, deprecate_obj, edge_collection, vertex_collection, rel_note):
        for obj in vertices:
            obj['_arango_cti_processor_note'] = rel_note
            obj['_record_md5_hash'] = processors.generate_md5(obj)
        inserted_ids, existing = self.arango.insert_several_objects_chunked(vertices, vertex_collection, chunk_size=1000)

        logging.info("removed %d already existing object", len(existing))
        self.arango.update_is_latest_several_chunked(inserted_ids, collection_name=vertex_collection, chunk_size=2000)
        logging.info("deprecating old relations")
        deprecated = self.deprecate_old_relations_chunked(deprecate_obj, edge_collection, rel_note)
        logging.info(f"deprecated {len(deprecated)} relationships")
        self.create_embedded_relationships([obj for obj in vertices if obj['id'] in inserted_ids], edge_collection, vertex_collection, rel_note)
        updated = self.arango.update_is_latest_for_embedded_refs([v[0] for v in deprecate_obj], edge_collection)

    def map_relationships(self, data, relate_function, collection_vertex, collection_edge, notes):
        objects_to_uploads = []
        processed_objects = [] # used for deprecation
        for obj in tqdm(data):
            if obj.get("type") not in [
                "relationship",
                "report",
                "identity",
                "marking-definition",
            ]:
                processed_objects.append([obj.get('id'), obj.get('_id')])
                objects_to_uploads += relate_function(
                    obj, self, collection_vertex, collection_edge, notes, **self.kwargs
                )

        edges, vertices = [], []
        for obj in objects_to_uploads:
            if obj['type'] == 'relationship':
                edges.append(obj)
            else:
                vertices.append(obj)
        self.upsert_several_objects_chunked(edges, processed_objects, collection_edge, rel_note=notes, collection_vertex=collection_vertex)
        self.upsert_several_vertices_chuncked(vertices, processed_objects, collection_edge, collection_vertex, rel_note=notes)
        # self.upsert_several_objects_chunked(objects_to_uploads, processed_objects, collection_edge, rel_note=notes, collection_vertex=collection_vertex)
        return objects_to_uploads
    
    def deprecate_old_relations(self, objects, collection, note):
        active_rels = dict(objects)
        query = """
        FOR doc in @@collection
        FILTER doc.type == 'relationship' AND doc._is_latest AND doc._arango_cti_processor_note == @note

        // deprecate all objects that point to a different ref._id other than source
        FILTER @active_rels[doc.source_ref] AND doc._from != @active_rels[doc.source_ref]


        UPDATE doc WITH {_is_latest: FALSE} in @@collection
        RETURN doc.id
        """

        return self.arango.execute_raw_query(query, bind_vars={
            "active_rels": active_rels,
            "@collection": collection,
            "note": note,
        })
    
    def deprecate_old_relations_chunked(self, objects, collection, note, chunk_size=1000):
        logging.info(f"Running deprecator for {len(objects)} items")
        progress_bar = tqdm(chunked(objects, chunk_size), total=len(objects))
        retval = []
        for chunk in progress_bar:
            retval.extend(self.deprecate_old_relations(chunk, collection, note))
            progress_bar.update(len(chunk))
        return retval
    
    def create_embedded_relationships(self, objects, collection, collection_vertex, rel_note):
        inserted_ids = [obj['id'] for obj in objects]
        if not objects or self.ignore_embedded_relationships:
            return []
        refs = processors.get_embedded_refs(objects[0])
        # print(refs, objects[0])

        result = self.arango.execute_raw_query("""
            FOR doc IN @@collection
            FILTER doc._is_latest AND doc.id IN @targets
            RETURN [doc.id, KEEP(doc, "id", "_id", "created", "modified")]
            """, 
            bind_vars={"targets": inserted_ids, "@collection": collection})
        
        result += self.arango.execute_raw_query("""
            FOR doc IN @@collection
            FILTER doc._is_latest AND doc.id IN @targets
            RETURN [doc.id, KEEP(doc, "id", "_id")]
            """, 
            bind_vars={"targets": list(set([target for _, target in refs])), "@collection": collection_vertex})
        
        id_map = dict(result)
        embedded_relationships = []
        # print(len(id_map))
        for obj in objects:
            for ref, target_id in refs:
                src, dst = id_map.get(obj['id']), id_map.get(target_id)
                if src and dst:
                    rel = processors.parse_relation_object(src, dst, None, relationship_type=ref, is_embedded_ref=True, note=rel_note)
                    rel['_stix2arango_note'] = self.stix2arango_note
                    embedded_relationships.append(rel)
        module_logger.info("inserting %d embedded relationships for %d objects", len(embedded_relationships), len(objects))
        inserted_ids, _ = self.arango.insert_several_objects_chunked(embedded_relationships, collection, chunk_size=1000)
        self.arango.update_is_latest_several_chunked(inserted_ids, collection_name=collection, chunk_size=2000)

        return embedded_relationships


def chunked(iterable, n):
    if not iterable:
        return []
    for i in range(0, len(iterable), n):
        yield iterable[i : i + n]
