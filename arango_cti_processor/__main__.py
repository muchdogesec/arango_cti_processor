import argparse
from .arango_processor import ArangoProcessor

def parse_arguments():
    parser = argparse.ArgumentParser(description="Import STIX JSON into ArangoDB")
    parser.add_argument("--database", required=False,
                        help="The arangoDB database name where the objects you want to link are found.")
    parser.add_argument("--relationship", required=False,
                        help="you can apply updates to certain collection at run time. "
                             "Default is all collections. User can select from; "
                             "mitre_attack_enterprise, mitre_attack_ics, "
                             "mitre_attack_mobile, mitre_capec, nvd_cpe, "
                             "nvd_cve, sigma_rules, disarm")
    parser.add_argument("--ignore_embedded_relationships", required=False,
                        help="This will stop any embedded relationships from being generated.")
    parser.add_argument("--arango_cti_processor_note", required=False,
                        help="Will be used as a value for `_arango_cti_processor_note` for all objects created by arango_cti_processor")
    return parser.parse_args()

def main():
    args = parse_arguments()
    stix_obj = ArangoProcessor(**args.__dict__)
    stix_obj.run()

if __name__ == "__main__":
    main()