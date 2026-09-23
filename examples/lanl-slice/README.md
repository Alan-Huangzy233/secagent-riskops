# LANL authentication slice (real data, public domain)

**Real data.** A slice of A. D. Kent, "Comprehensive, Multi-Source Cyber-Security
Events", Los Alamos National Laboratory, 2015, doi:10.17021/1179829, dedicated to
the public domain (CC0). Downloading it requires registering an intended use at
<https://csr.lanl.gov/data/cyber1/>, so the slice itself is not committed; what is
committed lets anyone with access rebuild it and check it byte for byte.

| File | What it is |
|---|---|
| `manifest-v2.json` | Slice rule version, seed, window, counts and the SHA-256 of every file the slicer writes |
| `episodes-v2.json` | The 74 red-team episodes in the window (one account on one day) |

Source files used:

| File | Size | SHA-256 |
|---|---|---|
| `auth.txt.gz` (`Last-Modified: 30 May 2024`) | 7,626,505,158 B; the slice needs only the first 3,200,000,000 B | first 3,200,000,000 B: `94f3008226e6ad5036de052d31146f2429d05287d5b3326614de586b350d0803` |
| `redteam.txt.gz` | 4,846 B | `606635837c684ad11e464075ecf97bc5df325ff7d7f64614d2d8c8af18051669` |

Rebuild:

```bash
python -m app.evaluation.lanl --auth auth.txt.gz --redteam redteam.txt.gz --out runtime-data/eval/lanl-v2
python -m app.evaluation.run --data runtime-data/eval/lanl-v2 --out docs/eval/results-lanl-v2.json
```

The slice rule is in the docstring of `backend/app/evaluation/lanl.py`: the three
consecutive days with the most red-team events (days 12–14), `LogOn` records
only, every record from the window's red-team sources plus a 2 % hash sample of
the other source computers. Version 1 (every record touching a red-team
computer) selected 15.3 million records because several targets are hubs and
was replaced before any evaluation ran.
