"""Об'єднує SARIF демонстраційних запусків і прив'язує знахідки до рядків demo/malicious-demo.txt."""
import json
import sys

out, target = sys.argv[1], "demo/malicious-demo.txt"
merged = None
for line, path in enumerate(sys.argv[2:], start=1):
    data = json.load(open(path, encoding="utf-8"))
    for r in data["runs"][0]["results"]:
        r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": target},
                                                "region": {"startLine": line}}}]
    if merged is None:
        merged = data
    else:
        merged["runs"][0]["results"] += data["runs"][0]["results"]
json.dump(merged, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
