import re

with open('dlp/evaluation/runner.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Remove deleted configuration attributes
text = re.sub(r'    config_default\.enable_structured_scan = True\n', '', text)
text = re.sub(r'    config_all\.enable_entropy = True\n', '', text)
text = re.sub(r'    config_all\.enable_ner = True\n', '', text)
text = re.sub(r'    config_all\.enable_fingerprinting = True\n', '', text)
text = re.sub(r'    config_all\.enable_structured_scan = True\n', '', text)
text = re.sub(r'            config\.enable_structured_scan = True\n', '', text)

with open('dlp/evaluation/runner.py', 'w', encoding='utf-8') as f:
    f.write(text)
