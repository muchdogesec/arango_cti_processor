import json, hashlib
import logging
import re

from arango.database import StandardDatabase
import requests
from stix2arango.services import ArangoDBService
import stix2

from arango_cti_processor import config

def generate_md5(obj: dict):
    obj_copy = {k: v for k, v in obj.items() if not k.startswith("_")}
    for k in ['_from', '_to', '_arango_cti_processor_note']:
        if v := obj.get(k):
            obj_copy[k] = v
    json_str = json.dumps(obj_copy, sort_keys=True, default=str).encode("utf-8")
    return hashlib.md5(json_str).hexdigest()

REQUIRED_COLLECTIONS = [
    'mitre_cwe_vertex_collection', 'mitre_cwe_edge_collection',
    'mitre_capec_vertex_collection', 'mitre_capec_edge_collection',
    'mitre_attack_enterprise_edge_collection', 'mitre_attack_enterprise_vertex_collection',
    'mitre_attack_ics_vertex_collection', 'mitre_attack_ics_edge_collection',
    'mitre_attack_mobile_vertex_collection', 'mitre_attack_mobile_edge_collection',
]

def validate_collections(db: 'StandardDatabase', collections=REQUIRED_COLLECTIONS):
    missing_collections = set()
    for collection in collections:
        try:
            db.collection(collection).info()
        except Exception as e:
            missing_collections.add(collection)
    if missing_collections:
        raise Exception(f"The following collections are missing. Please add them to continue. \n {missing_collections}")
    

def import_default_objects(processor: ArangoDBService, default_objects: list = None, collections=REQUIRED_COLLECTIONS):
    default_objects = list(default_objects or []) + config.DEFAULT_OBJECT_URL
    object_list = []
    for obj_url in default_objects:
        if isinstance(obj_url, str):
            obj = json.loads(load_file_from_url(obj_url))
        else:
            obj = obj_url
        obj['_arango_cti_processor_note'] = "automatically imported object at script runtime"
        obj['_record_md5_hash'] = generate_md5(obj)
        object_list.append(obj)

    for collection_name in collections:
        if not collection_name.endswith('vertex_collection'):
            continue
        inserted_ids, _ = processor.insert_several_objects(object_list, collection_name)
        processor.update_is_latest_several(inserted_ids, collection_name)

    

def load_file_from_url(url):
    response = requests.get(url)
    response.raise_for_status()  # Raise an HTTPError for bad responses
    return response.text
    
def stix2dict(obj: 'stix2.base._STIXBase'):
    return json.loads(obj.serialize())

EMBEDDED_RELATIONSHIP_RE = re.compile(r"([a-z_]+)_refs{0,1}")

def get_embedded_refs(object: list|dict, xpath: list = []):
    embedded_refs = []
    if isinstance(object, dict):
        for key, value in object.items():
            if key in ["source_ref", "target_ref"]:
                continue
            if match := EMBEDDED_RELATIONSHIP_RE.fullmatch(key):
                relationship_type = "-".join(xpath + match.group(1).split('_'))
                targets = value if isinstance(value, list) else [value]
                for target in targets:
                    embedded_refs.append((relationship_type, target))
            elif isinstance(value, list):
                embedded_refs.extend(get_embedded_refs(value, xpath + [key]))
    elif isinstance(object, list):
        for obj in object:
            if isinstance(obj, dict):
                embedded_refs.extend(get_embedded_refs(obj, xpath))
    return embedded_refs