import json
kb = json.load(open('data/unified/knowledge_base.json'))
for a in kb:
    if a.get('name') in ('APT41', 'BackdoorDiplomacy', 'POLONIUM'):
        ttps = a.get('ttps', [])
        has_t1071 = any(str(t).startswith('T1071') for t in ttps)
        print(f"{a.get('name'):20s} T1071 present: {has_t1071}  total TTPs: {len(ttps)}")
