"""
False-positive checklist: runs a fixed list of LEGITIMATE links through the same link pipeline the app uses and reports any
that come back Dangerous. Run it before and after every change to the rules or the models.

    cd backend
    python -m tools.false_positive_check                 # the whole list (about 3-5 minutes)
    python -m tools.false_positive_check --quick         # only links that never open a browser (seconds)
    python -m tools.false_positive_check --no-vt         # do not use VirusTotal (worst case, and spares its daily quota)
    python -m tools.false_positive_check --file my.txt   # another list;  --json report.json  saves the details

This tool is READ-ONLY: it changes no code, writes nothing to the database, does not touch the verdict memory or anyone's history
and does not call the AI service. The only thing it can create is the optional --json file you ask for.
Exit code: 0 = no Dangerous verdict, 1 = at least one legitimate link was called Dangerous.
"""
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)
os.chdir(BACKEND)                                   # the pipeline reads its files relative to backend/

DEFAULT_LIST = os.path.join(HERE, "legit_links.txt")


def load_links(path):
    items = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            items.append({"url": parts[0], "category": parts[1] if len(parts) > 1 else "", "note": parts[2] if len(parts) > 2 else ""})
    return items


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default=DEFAULT_LIST)
    ap.add_argument("--quick", action="store_true", help="skip links that would open a browser (trusted-domain answers only)")
    ap.add_argument("--no-vt", action="store_true", help="do not use VirusTotal")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--json", default="", help="also save the details to this file")
    args = ap.parse_args()

    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(BACKEND, ".env"))
    except Exception:
        pass
    os.environ["ENABLE_THREAT_SYNC"] = "false"       # never start the feed importer from here
    os.environ["ENABLE_LLM_REVIEW"] = "false"        # no AI calls
    if args.no_vt:
        os.environ.pop("VIRUSTOTAL_API_KEY", None)

    from core_engine.link_threat_pipeline import (get_link_pipeline, is_brand_fast_path, is_collab_platform,
                                                  is_trusted_view_page)
    pipeline = get_link_pipeline()
    links = load_links(args.file)
    if args.quick:
        links = [l for l in links if is_brand_fast_path(l["url"]) or is_collab_platform(l["url"]) or is_trusted_view_page(l["url"])]
    print(f"Checking {len(links)} legitimate links "
          f"({'without' if args.no_vt else 'with'} VirusTotal, {args.workers} at a time). Nothing is stored.\n", flush=True)

    def check(item):
        t0 = time.time()
        try:
            result = pipeline.analyze_url(item["url"], defer_ai=True)
            tel = result.get("telemetry") or {}
            return {**item, "verdict": result.get("display_verdict") or "?", "score": result.get("threat_score"),
                    "seconds": round(time.time() - t0, 1), "ml": tel.get("ml_probability"),
                    "override": tel.get("override_reason") or "", "capped": bool(tel.get("ml_capped_no_evidence")),
                    "summary": (result.get("summary") or "").replace("\n", " ")[:300]}
        except Exception as exc:                      # one broken link must not stop the checklist
            return {**item, "verdict": "ERROR", "score": None, "seconds": round(time.time() - t0, 1), "ml": None,
                    "override": "", "capped": False, "summary": f"{type(exc).__name__}: {exc}"[:300]}

    started = time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        results = []
        for res in pool.map(check, links):
            results.append(res)
            mark = {"Safe": "ok  ", "Dangerous": "FAIL", "ERROR": "ERR "}.get(res["verdict"], "warn")
            print(f"[{mark}] {res['verdict'][:26]:<26} {res['seconds']:>5}s  {res['url'][:78]}", flush=True)

    safe = [r for r in results if r["verdict"] == "Safe"]
    unverified = [r for r in results if r["verdict"].startswith("Unverified")]
    dangerous = [r for r in results if r["verdict"] == "Dangerous"]
    errors = [r for r in results if r["verdict"] == "ERROR"]
    print("\n" + "=" * 90)
    print(f"{len(results)} links in {int(time.time() - started)}s:  Safe {len(safe)}   Unverified {len(unverified)}   "
          f"DANGEROUS {len(dangerous)}   errors {len(errors)}")
    if dangerous:
        print("\nFALSE POSITIVES (legitimate links called Dangerous):")
        for r in dangerous:
            print(f"  - {r['url']}\n      score {r['score']}, model {r['ml']}, rule: {r['override'] or '-'}\n      {r['summary']}")
    if unverified:
        print("\nUnverified (not wrong, but not a clear Safe; the notes say which are known weak spots):")
        for r in unverified:
            note = f"   [{r['note']}]" if r["note"] else ""
            print(f"  - {r['url']}{note}")
    if errors:
        print("\nCould not be checked:")
        for r in errors:
            print(f"  - {r['url']}: {r['summary']}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"\nDetails saved to {args.json}")
    print("\nRESULT: " + ("PASS - no legitimate link was called Dangerous." if not dangerous else "FAIL - see the false positives above."))
    return 1 if dangerous else 0


if __name__ == "__main__":
    sys.exit(main())
