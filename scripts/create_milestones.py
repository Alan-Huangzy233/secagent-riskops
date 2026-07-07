import json
import subprocess
import sys

repo = sys.argv[1]
path = sys.argv[2]

milestones = json.load(open(path, encoding="utf-8"))

for m in milestones:
    title = m["title"]
    desc = m.get("description", "")
    # gh has no simple built-in milestone create in older versions.
    # Use GitHub API through gh.
    print("Creating milestone:", title)
    subprocess.run([
        "gh", "api",
        f"repos/{repo}/milestones",
        "-f", f"title={title}",
        "-f", f"description={desc}"
    ], check=False)
