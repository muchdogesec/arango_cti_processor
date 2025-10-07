import argparse
import itertools
from arango_cti_processor.managers import RELATION_MANAGERS
from stix2arango.services import ArangoDBService
from arango_cti_processor import config
from arango_cti_processor.tools.utils import import_default_objects, validate_collections

def parse_bool(value: str):
    value = value.lower()
    return value in ["yes", "y", "true", "1"]

def validate_modes(modes: str):
    modes = modes.split(",")
    for mode in modes:
        if mode not in RELATION_MANAGERS:
            raise argparse.ArgumentTypeError(f"unsupported mode `{mode}`, must be one or more of {list(RELATION_MANAGERS)}")
    return modes

def parse_arguments():
    parser = argparse.ArgumentParser(description="Import STIX JSON into ArangoDB")
    modes = list(RELATION_MANAGERS.keys())

    parser.add_argument(
        "--modes",
        "--relationship",
        required=False,
        help=f"you can apply updates to certain collection at run time. Default is all collections. Can select from; {modes}",
        type=validate_modes,
        default=modes,
    )

    parser.add_argument(
        "--ignore_embedded_relationships",
        required=False,
        help="This will stop any embedded relationships from being generated.",
        type=parse_bool,
    )
    
    parser.add_argument(
        "--database",
        required=True,
        help="the arangoDB database name where the objects you want to link are found. It must contain the collections required for the `--relationship` option(s) selected")
    parser.add_argument(
        "--version",
        metavar="VERSION",
        required=False,
        help="By default arango_cti_processor will consider all objects in the database specified with the property `_is_latest==true` (that is; the latest version of the object). Using this flag will allow actip to only consider objects where `_stix2arango_note == 'version=VERSION'`")
    
    return parser.parse_args()

def run_all(database=None, modes: list[str]=None, **kwargs):
    processor = ArangoDBService(database, [], [], host_url=config.ARANGODB_HOST_URL, username=config.ARANGODB_USERNAME, password=config.ARANGODB_PASSWORD)
    collections = list(itertools.chain(*[RELATION_MANAGERS[mode].required_collections for mode in modes]))
    validate_collections(processor.db, collections=collections)
    
    import_default_objects(processor, default_objects=list(itertools.chain(*[RELATION_MANAGERS[mode].default_objects for mode in modes])), collections=collections)
    manager_klasses = sorted([RELATION_MANAGERS[mode] for mode in modes], key=lambda manager: manager.priority)
    for manager_klass in manager_klasses:
        relation_manager = manager_klass(processor, **kwargs)
        relation_manager.process()

def main():
    args = parse_arguments()
    run_all(**args.__dict__)

