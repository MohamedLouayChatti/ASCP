import json
with open('dlp/evaluation/corpus.json', 'r', encoding='utf-8') as f:
    corpus = json.load(f)
count=0
for tc in corpus['test_cases']:
    if tc.get('expected_action') == 'ESCALATE':
        print(tc['id'])
        count+=1
print(count)
