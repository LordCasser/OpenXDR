#!/usr/bin/env python3
"""预先固定顺序的格式对照复测；不根据模型回答修改模板。"""
import argparse
import hashlib
import json
import pathlib
import random
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--study', choices=['formats', 'revocation'], default='formats')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = pathlib.Path(__file__).resolve().parents[2]
    if args.study == 'revocation':
        frozen = json.loads((root / 'validation/ssh-decoy/evidence/round9-plan.json').read_text())['frozen']
        conditions = ['operator-revoke-v1', 'operator-close-v1']
    else:
        frozen = json.loads((root / 'validation/ssh-decoy/evidence/round4-template-freeze.json').read_text())
        conditions = ['inject-en-v1', 'format-v1', 'internal-v1']
    for name, digest in frozen.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError('冻结文件发生变化：' + name)
    rng = random.Random(20261019)
    order = []
    for block in range(1, 4):
        templates = list(conditions)
        rng.shuffle(templates)
        order.extend({'block': block, 'template': template} for template in templates)
    plan = {'study': args.study, 'seed': 20261019, 'order': order, 'frozen': frozen,
            'provider': 'glm53-h20', 'model': 'ZhipuAI/GLM-5.3-Flash',
            'command_turns': 1, 'max_tokens': 16384, 'request_timeout': 180, 'trial_seconds': 210}
    (args.output / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    for index, item in enumerate(order, 1):
        target = args.output / f"{index:02d}-block{item['block']}-{item['template']}"
        command = [sys.executable, str(root / 'validation/ssh-decoy/evaluate.py'),
                   '--output', str(target), '--providers', plan['provider'], '--model-id', plan['model'],
                   '--frameworks', 'boxpwnr', '--templates', item['template'], '--seed-tool', 'nmap-auth',
                   '--command-turns', '1', '--max-tokens', '16384', '--request-timeout', '180', '--trial-seconds', '210']
        print(f"trial {index}/{len(order)}: {item['template']}", flush=True)
        subprocess.run(command, check=True, cwd=root)


if __name__ == '__main__':
    main()
