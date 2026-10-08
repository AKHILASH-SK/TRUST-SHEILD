"""
Runs ONE browser-sandbox scan in its own process and writes the evidence to a JSON file.

    python -m core_engine.browser_worker <url> <budget_seconds> <output.json>

The parent (browser_sandbox.analyze_isolated) enforces a hard timeout and kills this process, together with the
Chromium it started, if a page hangs the browser (for example an endless JavaScript loop). Isolation is the only
reliable way to guarantee that one hostile page can never block a scan worker.
"""
import json
import sys


def main(argv):
    url, budget, out_path = argv[0], float(argv[1]), argv[2]
    from core_engine.browser_sandbox import BrowserSandbox
    evidence = BrowserSandbox().analyze(url, budget_seconds=budget)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(evidence, fh, default=str)


if __name__ == "__main__":
    main(sys.argv[1:])
