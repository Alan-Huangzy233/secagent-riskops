import json
import subprocess
import sys

repo = sys.argv[1]
path = sys.argv[2]

labels = json.load(open(path, encoding="utf-8"))

for label in labels:
    name = label["name"]
    color = label["color"]
    desc = label.get("description", "")
    cmd = [
        "gh", "label", "create", name,
        "--repo", repo,
        "--color", color,
        "--description", desc,
        "--force"
    ]
    print("Creating/updating label:", name)
    subprocess.run(cmd, check=True)
