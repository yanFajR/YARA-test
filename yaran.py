import yara

# Load YARA rule file

malware_types = []
with open('1d241ce6671ec9018b2972ac9e120748', 'rb') as f:
    data = f.read()
    
rule_paths = {'malware': 'rules/malware_index.yar', 
              'exploit_kits': 'rules/exploit_kits_index.yar', 
              'mobile_malware': 'rules/mobile_malware_index.yar', 
              'packers': 'rules/packers_index.yar', 
              'webshells': 'rules/webshells_index.yar'}
rules = yara.compile(filepaths=rule_paths)
matches = rules.match(data=data)

# Check if matches were found
if matches:
    for match in matches:
        malware_types.append(f"{match.namespace}/{match.rule}")
    print(malware_types)
else:
    print("No malware found.")