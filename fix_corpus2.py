import json

with open('dlp/evaluation/corpus.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

for tc in data['test_cases']:
    if 'escalate' in tc['id'] and 'secret' not in tc.get('expected_violations', []) and 'canary' not in tc.get('expected_violations', []):
        tc['expected_action'] = 'ESCALATE'

with open('dlp/evaluation/corpus.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)
