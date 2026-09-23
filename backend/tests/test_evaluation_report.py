"""Published numbers are rendered from results.json and cannot drift from it."""
from __future__ import annotations

import io
import json

import pytest

from app.evaluation import demo, report


def test_only_the_text_between_markers_is_replaced():
    text = "intro\n<!-- generated:a -->\nold\n<!-- /generated:a -->\nmiddle\n<!-- generated:b -->\n<!-- /generated:b -->\n"
    updated, used = report.refresh(text, {"a": "new A\n", "b": "new B\n"})
    assert updated == ("intro\n<!-- generated:a -->\nnew A\n<!-- /generated:a -->\nmiddle\n"
                       "<!-- generated:b -->\nnew B\n<!-- /generated:b -->\n")
    assert used == {"a", "b"}
    assert report.refresh(updated, {"a": "new A\n", "b": "new B\n"})[0] == updated


def test_a_marker_without_a_renderer_is_an_error():
    with pytest.raises(KeyError):
        report.refresh("<!-- generated:nope -->\n<!-- /generated:nope -->", {})


def test_the_committed_documents_match_the_committed_results():
    assert report.main(["--check"]) == 0


def test_the_readme_headline_quotes_the_synthetic_results():
    results = {name: json.loads(path.read_text()) for name, path in report.RESULTS.items()}
    line = report.readme(results)
    surfaced = results["synthetic"]["systems"]["pipeline, surfaced"]
    assert f"**{surfaced['reduction']['output_incidents']} incidents surfaced" in line
    assert f"{surfaced['detection']['tau_0.5']['detected']} of {surfaced['detection']['tau_0.5']['episodes']}" in line
    assert "miss rate" in line and "EVALUATION.md" in line


def test_the_demo_ends_with_the_comparison():
    out = io.StringIO()
    assert demo.run(out) == 0
    text = out.getvalue()
    assert "B1 tuple dedup" in text and "SecAgent RiskOps, surfaced" in text
    assert "attacks caught" in text and "miss rate" in text and "EVALUATION.md" in text
