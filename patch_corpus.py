import json

with open('dlp/evaluation/corpus.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Update design principles
if "_comment" in data:
    if "design_principles" in data:
        data["design_principles"] = [
            "Balance the corpus across ALLOW, REDACT, ESCALATE, and BLOCK.",
            "Reward contextual understanding so obvious examples, placeholders, and fake values can be ALLOW.",
            "Treat limited PII as REDACT, bulk or high-risk disclosure as ESCALATE, and real secret or canary leakage as BLOCK regardless of intent."
        ]
    if "distribution_targets" in data:
        data["distribution_targets"] = {
            "total_cases": 96,
            "per_expected_action": 24
        }

action_counts = {}

for tc in data['test_cases']:
    if 'category' in tc:
        del tc['category']
    
    expected = tc['expected_action'].lower()
    if expected not in action_counts:
        action_counts[expected] = 1
    else:
        action_counts[expected] += 1
    
    num = str(action_counts[expected]).zfill(2)
    tc['id'] = f"{expected}-{num}"

with open('dlp/evaluation/corpus.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)
