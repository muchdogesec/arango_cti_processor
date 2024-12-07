1. import latest required data

In stix2arango run

```shell
python3 utilities/arango_cti_processor/insert_archive_attack_enterprise.py \
	--database arango_cti_processor \
	--versions 16_0 \
	--ignore_embedded_relationships True && \
python3 utilities/arango_cti_processor/insert_archive_attack_ics.py \
	--database arango_cti_processor \
	--versions 16_0 \
	--ignore_embedded_relationships True && \
python3 utilities/arango_cti_processor/insert_archive_attack_mobile.py \
	--database arango_cti_processor \
	--versions 16_0 \
	--ignore_embedded_relationships True && \
python3 utilities/arango_cti_processor/insert_archive_capec.py \
	--database arango_cti_processor \
	--versions 3_9 \
	--ignore_embedded_relationships True && \
python3 utilities/arango_cti_processor/insert_archive_cwe.py \
	--database arango_cti_processor \
	--versions 4_16 \
	--ignore_embedded_relationships True
```

2. generate relationships

In arango_cti_processor run

```shell
python3 arango_cti_processor.py \
    --database arango_cti_processor_database \
    --relationship capec-attack \
    --ignore_embedded_relationships true && \
python3 arango_cti_processor.py \
    --database arango_cti_processor_database \
    --relationship cwe-capec \
    --ignore_embedded_relationships true
```

3. check imports

```sql
FOR doc IN mitre_capec_edge_collection
    FILTER doc._arango_cti_processor_note == "capec-attack"
    RETURN doc
```

```sql
FOR doc IN mitre_cwe_edge_collection
    FILTER doc._arango_cti_processor_note == "cwe-capec"
    RETURN doc
```