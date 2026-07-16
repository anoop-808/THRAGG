import subprocess
import sys

res = subprocess.run(["pytest", "tests/test_attack_chain.py"], capture_output=True, text=True)
print(res.stdout)
if res.stderr:
    print(res.stderr)
