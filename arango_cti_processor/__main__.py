import argparse
from .arango_processor import ArangoProcessor

def parse_arguments():
    parser = argparse.ArgumentParser(description="Import STIX JSON into ArangoDB")
    parser.add_argument("--database", required=True,
                        help="The arangoDB database name where the objects you want to link are found.")
    parser.add_argument("--relationship", required=False,
                        help="you can apply updates to certain collection at run time. "
                             "Default is all collections. Can select from; "
                             "capec-attack"
                             "capec-cwe"
                             "cwe-capec"
                             "attack-capec"
                             "cve-cwe"
                             "cve-cpe"
                             "sigma-attack"
                             "sigma-cve"
                             "cve-attack"
                        )
    parser.add_argument("--ignore_embedded_relationships", required=False,
                        help="This will stop any embedded relationships from being generated.")
    parser.add_argument("--stix2arango_note", required=False,
                        help="Will be used as a value for `_stix2arango_note` for all objects created by arango_cti_processor")
    return parser.parse_args()

def main():
    args = parse_arguments()
    stix_obj = ArangoProcessor(**args.__dict__)
    stix_obj.run()

if __name__ == "__main__":
    main()