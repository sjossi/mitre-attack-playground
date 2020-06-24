from stix2 import FileSystemSource, Filter
import csv

datasources = {}

fs = FileSystemSource('./cti/enterprise-attack')
filt = Filter('type', '=', 'attack-pattern')
techniques = fs.query([filt])

for technique in techniques:
    try: 
        for datasource in technique.x_mitre_data_sources:
            if datasource not in datasources:
                datasources[datasource] = []
            for reference in technique.external_references:
                if reference.source_name == 'mitre-attack':
                    datasources[datasource].append([technique.name, technique.description, reference.external_id, reference.url])
    except AttributeError:
        pass

print("datasource\ttechnique-name\ttechnique description\ttechnique id\ttechnique url")
for datasource in datasources:
    for technique in datasources[datasource]:
        print("\"{}\"\t\"{}\"\t\"{}\"\t\"{}\"\t\"{}\"".format(datasource, technique[0], technique[1], technique[2], technique[3]))