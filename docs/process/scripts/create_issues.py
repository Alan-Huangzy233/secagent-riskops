import json
import subprocess
import sys
from pathlib import Path

repo = sys.argv[1]
path = sys.argv[2]

issues = json.load(open(path, encoding="utf-8"))

for issue in issues:
    title = issue["title"]
    body = issue["body"]
    labels = issue.get("labels", [])
    milestone = issue.get("milestone")

    cmd = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body]

    for label in labels:
        cmd += ["--label", label]

    if milestone:
        cmd += ["--milestone", milestone]

    print("Creating issue:", title)
    subprocess.run(cmd, check=True)
