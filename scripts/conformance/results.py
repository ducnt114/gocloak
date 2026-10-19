#!/usr/bin/env python3
"""Prints the results of conformance suite plans and fails (exit 1) when a
module failed or did not finish. REVIEW (screenshots awaiting a human
reviewer) and WARNING results are accepted.

usage: results.py SUITE_URL PLAN_ID...
"""
import json
import ssl
import sys
import urllib.request

ctx = ssl._create_unverified_context()  # the suite runs with a self-signed certificate
base = sys.argv[1].rstrip("/")


def get(path):
    return json.load(urllib.request.urlopen(base + path, context=ctx))


ok = True
for plan_id in sys.argv[2:]:
    plan = get("/api/plan/" + plan_id)
    print("plan", plan.get("planName"), plan_id)
    for m in plan["modules"]:
        for inst in m.get("instances", []):
            info = get("/api/info/" + inst)
            result, status = str(info.get("result")), info.get("status")
            print(f"  {result:9} {status:11} {m['testModule']}")
            if status != "FINISHED" or result not in ("PASSED", "WARNING", "REVIEW"):
                ok = False
                for e in get("/api/log/" + inst):
                    if e.get("result") in ("FAILURE", "INTERRUPTED"):
                        print("     ", e.get("result"), e.get("src"), "|", (e.get("msg") or "")[:300])
sys.exit(0 if ok else 1)
