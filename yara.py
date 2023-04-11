import yara

# Load YARA rule file
rules = yara.compile('rules/malware_index.yar')

# Open file to scan
with open('0141221fee4f37699898e50188b07df2', 'rb') as f:
    data = f.read()

# Scan file using YARA rules
matches = rules.match(data=data)

# Check if matches were found
if matches:
    print("Malware detected!")
    for match in matches:
        print(match)
else:
    print("No malware found.")