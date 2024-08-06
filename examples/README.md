# Examples

This file contains some example searches to help you get you up and running with Arango CTI Processor

You should import the data as follows;

If you just want the latest data (at the time of writing), this command ([run using stix2arango](https://github.com/muchdogesec/stix2arango)) will give you what you need;

```shell
python3 utilities/arango_cti_processor/insert_archive_attack_enterprise.py \
	--database cti \
	--versions 15_1 \
    --ignore_embedded_relationships true && \
python3 utilities/arango_cti_processor/insert_archive_attack_ics.py \
	--database cti \
	--versions 15_1 \
    --ignore_embedded_relationships true && \
python3 utilities/arango_cti_processor/insert_archive_attack_mobile.py \
	--database cti \
	--versions 15_1 \
    --ignore_embedded_relationships true && \
python3 utilities/arango_cti_processor/insert_archive_capec.py \
	--database cti \
	--versions 3_9 \
    --ignore_embedded_relationships true && \
python3 utilities/arango_cti_processor/insert_archive_cwe.py \
	--database cti \
	--versions 4_14 \
    --ignore_embedded_relationships true && \
python3 utilities/arango_cti_processor/insert_archive_disarm.py \
	--database cti \
	--versions 1_4 \
    --ignore_embedded_relationships true && \
python3 utilities/arango_cti_processor/insert_archive_locations.py \
	--database cti \
    --ignore_embedded_relationships true && \
python3 utilities/arango_cti_processor/insert_archive_sigma_rules.py \
	--database cti \
	--versions 2024-07-17 \
    --ignore_embedded_relationships true && \
python3 utilities/arango_cti_processor/insert_archive_yara_rules.py \
	--database cti \
	--versions 0f93570 \
    --ignore_embedded_relationships true && \
python3 utilities/arango_cti_processor/insert_archive_cve.py \
	--database cti \
	--ignore_embedded_relationships false \
	--years 2017,2018,2019,2020,2021,2022,2023,2024 && \
python3 utilities/arango_cti_processor/insert_archive_cpe.py \
	--database cti \
	--ignore_embedded_relationships false
```

Note, old products are often referenced in CVEs, so to be safe, all CPE data is downloaded.

CVEs are downloaded from 2017, as this is the earliest CVE year referenced in a Sigma rule.

## CAPEC -> ATT&CK

## CAPEC -> CWW

## CWE -> CAPEC

## ATT&CK -> CAPEC

## CVE -> CWE

```shell
python3 arango_cti_processor.py \
	--database cti_database \
	--relationship cve-cwe \
	--ignore_embedded_relationships false
```

## CVE -> CPE

## Sigma -> ATT&CK

```shell
python3 arango_cti_processor.py \
	--database cti_database \
	--relationship sigma-attack \
	--ignore_embedded_relationships false
```

Count ATT&CK IDs used in Sigma Rules:

```sql
FOR edge IN sigma_rules_edge_collection
    FILTER edge._is_latest == true
    AND edge._arango_cti_processor_note == "sigma-attack"
    
    // Lookup the _from vertex document
    LET fromVertex = DOCUMENT(edge._from)
    
    // Lookup the _to vertex document
    LET toVertex = DOCUMENT(edge._to)
    
    // Extract the external_id from the external_references where source_name is "mitre-attack"
    LET externalId = FIRST(
        FOR ref IN toVertex.external_references
            FILTER ref.source_name == "mitre-attack"
            RETURN ref.external_id
    )
    
    COLLECT attackId = externalId, attackName = toVertex.name INTO groupedResults = {
        "Sigma Rule Name": fromVertex.name
    }
    
    LET countSigmaRules = LENGTH(groupedResults)
    
    SORT countSigmaRules DESC
    
    RETURN {
        "ATT&CK Object": CONCAT(attackId, " - ", attackName),
        "Count of Sigma Rule Names": countSigmaRules
    }
```

Show Sigma Rules by ATT&CK IDs

```sql
FOR edge IN sigma_rules_edge_collection
    FILTER edge._is_latest == true
    AND edge._arango_cti_processor_note == "sigma-attack"
    
    // Lookup the _from vertex document
    LET fromVertex = DOCUMENT(edge._from)
    
    // Lookup the _to vertex document
    LET toVertex = DOCUMENT(edge._to)
    
    // Extract the external_id from the external_references where source_name is "mitre-attack"
    LET externalId = FIRST(
        FOR ref IN toVertex.external_references
            FILTER ref.source_name == "mitre-attack"
            RETURN ref.external_id
    )
    
    // Extract the id from the external_references where source_name is "sigma-rule" and external_id is "id"
    LET sigmaRuleId = FIRST(
        FOR ref IN fromVertex.external_references
            FILTER ref.source_name == "sigma-rule" AND ref.external_id == "id"
            RETURN ref.description
    )
    
    // Create the concatenated ATT&CK Object
    LET attackObject = CONCAT(externalId, " - ", toVertex.name)
    
    // Create the concatenated Sigma Rule Name with ID
    LET sigmaRuleNameWithId = CONCAT(fromVertex.name, " (", sigmaRuleId, ")")
    
    // Sort the results by "ATT&CK Object"
    SORT attackObject
    
    RETURN {
        "Sigma Rule Name": sigmaRuleNameWithId,
        "Sigma Rule STIX ID": fromVertex.id,
        "ATT&CK Object": attackObject,
        "ATT&CK STIX ID": toVertex.id
    }
```

Take a Sigma Rule (by name) and find out what ATT&CK objects it's linked to;

```sql
// Step 1: Find the vertex document for "Net.EXE Execution"
LET sigmaVertex = FIRST(
    FOR vertex IN sigma_rules_vertex_collection
    FILTER vertex.name == "Net.EXE Execution"
    RETURN vertex
)

// Step 2: Find all related edges in the sigma_rules_edge_collection
LET relatedEdges = (
    FOR edge IN sigma_rules_edge_collection
    FILTER edge._from == sigmaVertex._id
    RETURN edge
)

// Step 3: Retrieve the target MITRE ATT&CK object IDs, names, and external IDs from these edges
LET mitreAttackObjects = (
    FOR edge IN relatedEdges
    LET targetVertex = DOCUMENT(edge._to)
    LET externalId = FIRST(
        FOR ref IN targetVertex.external_references
        FILTER ref.source_name == "mitre-attack"
        RETURN ref.external_id
    )
    RETURN {
        "ATT&CK Name": targetVertex.name,
        "ATT&CK ID": externalId,
        "ATT&CK STIX ID": targetVertex.id
    }
)

RETURN mitreAttackObjects
```

Take a Sigma Rule (by name) and find out what ATT&CK objects it's linked to but this time print the entire STIX object;

```sql
// Step 1: Find the vertex document for "Net.EXE Execution"
LET sigmaVertex = FIRST(
    FOR vertex IN sigma_rules_vertex_collection
    FILTER vertex.name == "Net.EXE Execution"
    RETURN vertex
)

// Step 2: Find all related edges in the sigma_rules_edge_collection
LET relatedEdges = (
    FOR edge IN sigma_rules_edge_collection
    FILTER edge._from == sigmaVertex._id
    RETURN edge
)

// Step 3: Retrieve the target MITRE ATT&CK objects from these edges
LET mitreAttackObjects = (
    FOR edge IN relatedEdges
    LET targetVertex = DOCUMENT(edge._to)
    LET externalId = FIRST(
        FOR ref IN targetVertex.external_references
        FILTER ref.source_name == "mitre-attack"
        RETURN ref.external_id
    )
    RETURN MERGE(
        UNSET(targetVertex, [
            "_key", "_id", "_rev", "_bundle_id", "_file_name", "_stix2arango_note",
            "_record_md5_hash", "_is_latest", "_record_created", "_record_modified"
        ]),
        { "ATT&CK External ID": externalId }
    )
)

RETURN mitreAttackObjects
```

Or do it the other way around; take an ATT&CK ID and find out what Sigma Rules are linked to it

```sql
// Step 1: Find the MITRE ATT&CK object(s) with the specified ATT&CK ID
LET attackObjects = (
    FOR attackVertex IN mitre_attack_enterprise_vertex_collection
    FILTER attackVertex.external_references[*].external_id ANY == "T1055"
    RETURN attackVertex._id
)

// Step 2: Find all related edges in the sigma_rules_edge_collection
LET relatedEdges = (
    FOR edge IN sigma_rules_edge_collection
    FILTER edge._to IN attackObjects
    RETURN edge
)

// Step 3: Retrieve the Sigma rule names, STIX IDs, and Sigma rule IDs from these edges
LET sigmaRules = (
    FOR edge IN relatedEdges
    LET sigmaVertex = DOCUMENT(edge._from)
    LET sigmaRuleId = FIRST(
        FOR ref IN sigmaVertex.external_references
        FILTER ref.source_name == "sigma-rule" AND ref.external_id == "id"
        RETURN ref.description
    )
    RETURN {
        "Sigma Rule Name": sigmaVertex.name,
        "Sigma Rule STIX ID": sigmaVertex.id,
        "Sigma Rule ID": sigmaRuleId
    }
)

RETURN UNIQUE(sigmaRules)
```

You could also view this data in graphical format using the STIX id for the ATT&CK objects, e.g. for T1055

```sql
FOR doc IN sigma_rules_edge_collection
    FILTER doc._is_latest == true
    AND doc._arango_cti_processor_note == "sigma-attack"
    AND doc.target_ref == "attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d"
    RETURN doc
```

## Sigma -> CVE

```shell
python3 arango_cti_processor.py \
	--database cti_database \
	--relationship sigma-cve \
	--ignore_embedded_relationships false
```

Return all Sigma Rules and descriptions of the CVEs they're related to

```sql
// Step 1: Find all relevant edges
LET relevantEdges = (
    FOR edge IN sigma_rules_edge_collection
    FILTER edge._is_latest == true
    AND edge._arango_cti_processor_note == "sigma-cve"
    RETURN edge
)

// Step 2: Retrieve the Sigma rule names, IDs, STIX IDs, and CVE descriptions
LET sigmaCvePairs = (
    FOR edge IN relevantEdges
    LET sigmaRule = DOCUMENT(edge._from)
    LET cve = DOCUMENT(edge._to)
    RETURN {
        "Sigma Rule Name": sigmaRule.name,
        "Sigma Rule STIX ID": sigmaRule.id,
        "CVE Name": cve.name,
        "CVE Description": cve.description
    }
)

// Return the result as a table
RETURN sigmaCvePairs
```

Or take a CVE ID, and find out what Sigma Rules are known to detect it;

```sql
// Step 1: Find the CVE document with the name 'CVE-2023-22518'
LET cveDoc = FIRST(
    FOR cve IN nvd_cve_vertex_collection
    FILTER cve.name == "CVE-2023-22518"
    AND cve.type == "vulnerability"
    RETURN cve
)

// Step 2: Find all edges that reference this CVE document
LET relatedEdges = (
    FOR edge IN sigma_rules_edge_collection
    FILTER edge._to == cveDoc._id
    AND edge._is_latest == true
    AND edge._arango_cti_processor_note == "sigma-cve"
    RETURN edge
)

// Step 3: Retrieve the Sigma rule names, IDs, and STIX IDs from these edges
LET sigmaRuleDetails = (
    FOR edge IN relatedEdges
    LET sigmaRule = DOCUMENT(edge._from)
    RETURN {
        "Sigma Rule Name": sigmaRule.name,
        "Sigma Rule STIX ID": sigmaRule._id
    }
)

// Return the result
RETURN UNIQUE(sigmaRuleDetails)
```

You could also view this data in graphical format using the STIX id for the CVE objects, e.g. for CVE-2023-22518

```sql
FOR doc IN sigma_rules_edge_collection
    FILTER doc._is_latest == true
    AND doc._arango_cti_processor_note == "sigma-cve"
    AND doc.target_ref == "vulnerability--5bcfdb23-a585-558f-beb1-d408a99b6e61"
    RETURN doc
```

_assuming you've run cve-cwe you can also now see what weaknesses are exploited by cves related to a Sigma Rule..._

You can see what CWEs are related to CVE-2023-22518 as follows 

```sql
FOR doc IN nvd_cve_edge_collection
    FILTER doc._is_latest == true
    AND doc._arango_cti_processor_note == "cve-cwe"
    AND doc.source_ref == "vulnerability--5bcfdb23-a585-558f-beb1-d408a99b6e61"
    RETURN doc
```

With this we can now take a Sigma Rule name, show what CVEs it detects, and finally show what weaknesses are related to the CVEs so that we can potentially improve the Sigma Rule (or add another) to detect the weaknesses

So here we know the sigma rule name CVE-2023-22518 Exploitation Attempt - Vulnerable Endpoint Connection (Webserver) is related to CVE-2023-22518 and that CVE is linked CWE-863. Lets write a query to visualise this...

```sql
// Step 1: Find the Sigma Rule document
LET sigmaRuleDoc = FIRST(
    FOR sigma IN sigma_rules_vertex_collection
    FILTER sigma.name == "CVE-2023-22518 Exploitation Attempt - Vulnerable Endpoint Connection (Webserver)"
    RETURN sigma
)

// Step 2: Find all CVEs related to this Sigma Rule
LET relatedCVEs = (
    FOR edge IN sigma_rules_edge_collection
    FILTER edge._from == sigmaRuleDoc._id
    AND edge._is_latest == true
    AND edge._arango_cti_processor_note == "sigma-cve"
    LET cveDoc = DOCUMENT(edge._to)
    RETURN cveDoc
)

// Step 3: For each CVE, find all related CWEs and their CWE IDs
LET relatedCWEs = (
    FOR cve IN relatedCVEs
    LET cweEdges = (
        FOR edge IN nvd_cve_edge_collection
        FILTER edge._is_latest == true
        AND edge._arango_cti_processor_note == "cve-cwe"
        AND edge.source_ref == cve.id
        LET cweDoc = DOCUMENT(edge._to)
        RETURN {
            "CWE ID": (
                FOR ref IN cweDoc.external_references
                FILTER ref.source_name == "cwe"
                RETURN ref.external_id
            )[0], // Select the first matching CWE ID, if available
            "CWE Name": cweDoc.name,
            "CWE Description": cweDoc.description
        }
    )
    RETURN {
        "CVE Name": cve.name,
        "CVE Description": cve.description,
        "Related CWEs": cweEdges
    }
)

// Final result: Sigma Rule, related CVEs, and their related CWEs
RETURN {
    "Sigma Rule Name": sigmaRuleDoc.name,
    "Sigma Rule ID": sigmaRuleDoc.id,
    "Related CVEs": relatedCWEs
}
```