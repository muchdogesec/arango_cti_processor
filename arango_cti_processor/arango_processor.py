import os
import json

import logging

from . import config
from tqdm import tqdm
from stix2arango.services.arangodb_service import ArangoDBService
from jsonschema import validate


from . import utils as processors
module_logger = logging.getLogger("data_ingestion_service")


class ArangoProcessor:

    def __init__(self, **kwargs):
        self.relationship = kwargs.get("relationship") if kwargs.get("relationship", None) else None
        self.ignore_embedded_relationships = kwargs.get("ignore_embedded_relationships") if kwargs.get("ignore_embedded_relationships", None) else None
        self.arango_cti_processor_note = kwargs.get("arango_cti_processor_note") if kwargs.get("arango_cti_processor_note", None) else ""

        self.arango = ArangoDBService(config.ARANGODB_DATABASE, config.COLLECTION_VERTEX, config.COLLECTION_EDGE, relationship=self.relationship)

    def finalize_collections(self):
        if not config.SMET_ACTIVATE:
            logging.warning("SMET not activated, cve-attack relationships will not be processed")

        relations_needs_to_run=[]
        if self.relationship:
            if self.relationship != "cpe-groups":
                for key, value in processors.get_rel_func_mapping().get(self.relationship).items():
                    relations_needs_to_run.append([key, value])
        else:
            for vertex in processors.get_relationship().keys():
                for rel, func in processors.get_relationship().get(vertex).items():
                    relations_needs_to_run.append([vertex, func])
                break
        return relations_needs_to_run

    def default_objects(self):
        object_list = []
        for obj in config.DEFAULT_OBJECT_URL:
            data = json.loads(processors.load_file_from_url(obj))
            object_list.append(data)

        return object_list

    def get_is_latest(self, data, collection):

        for _type, obj, modified in tqdm(data):
            try:
                processors.set_latest_for(self.arango, obj, collection)
            except Exception as e:
                pass

    def process_bundle_into_graph(self, filename: str, core_collection_vertex:str, data=None, notes=None):

        if data.get("type", None) != "bundle":
            module_logger.error("Provided file is not a STIX bundle. Aborted")
            return False

        objects = []
        insert_data = []  # That would be the overall statement
        for obj in tqdm(data["objects"]):
            query = f"FOR doc in {core_collection_vertex} \n" \
                    f"FILTER doc.id =='{obj.get('id')}' AND " \
                    f"doc._record_md5_hash == '{processors.generate_md5(obj)}' \n" \
                    "RETURN doc"
            result = self.arango.execute_raw_query(query)
            if len(result)==0:
                if obj.get("type") not in ["relationship"]:
                    obj['_arango_cti_processor_note'] = notes
                    obj['_record_md5_hash'] = processors.generate_md5(obj)
                    objects.append(obj)
                    insert_data.append([
                            obj.get("type"), obj.get("id"),
                            True if "modified" in obj else False])

        module_logger.info(f"Inserting objects into database. Total objects: {len(objects)}")
        self.arango.upsert_several_objects_chunked(objects, core_collection_vertex)
        if len(insert_data)>0:
            self.get_is_latest(insert_data, core_collection_vertex)

    def run(self):
        if not self.arango.missing_collection:
            return

        logging.info("Processing default objects now")
        for collect in config.COLLECTION_VERTEX:
            logging.info(f"Checking: {collect}")
            self.process_bundle_into_graph(
                filename="",
                data={
                    "type": "bundle",
                    "objects": self.default_objects()
                },
                notes="automatically imported object at script runtime",
                core_collection_vertex=collect
            )

        logging.info("Processing relationships now")
        for vertex, func in self.finalize_collections():
            logging.info(f"Checking: {vertex}")
            query = f"for doc in {vertex} FILTER doc._is_latest==true return doc"
            data = self.arango.execute_raw_query(query=query)
            inserted_data = self.arango.map_relationships(
                data=data,
                func=func,
                collection_vertex=vertex,
                collection_edge=vertex.replace("vertex", "edge"),
                notes=self.arango_cti_processor_note
            )
            print("inserted_data:", inserted_data)
            self.get_is_latest(inserted_data, vertex.replace("vertex", "edge"))
            self.get_is_latest(inserted_data, vertex)
            if "cpe" in vertex:
                inserted_data = processors.cpe_groups(self.arango)
                self.get_is_latest(inserted_data, vertex)
            if "sigma" in vertex:
                processors.sigma_groups(self.arango)

        if self.relationship =="cpe-groups":
            inserted_data = processors.cpe_groups(self.arango)
            self.get_is_latest(inserted_data, "nvd_cpe_vertex_collection")