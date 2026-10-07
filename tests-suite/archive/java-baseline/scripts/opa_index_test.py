#!/usr/bin/env python3
"""OPA Index Verification Experiment - Fixed version"""

import json
import sys
import urllib.request
import time

OPA_URL = "http://localhost:8181"

def opa_request(method, path, data=None, content_type="application/json"):
    url = f"{OPA_URL}{path}"
    if isinstance(data, str):
        body = data.encode()
    elif data:
        body = json.dumps(data).encode()
    else:
        body = None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return {"error": f"HTTP {e.code}: {body}"}
    except Exception as e:
        return {"error": str(e)}

def push_policy():
    rego = """package astralbench

default allow := false

deny_exists if {
    some i
    input.card_id == data.bindings[i].card_id
    input.resource == data.bindings[i].resource
    input.action == data.bindings[i].action
    data.bindings[i].effect == "deny"
}

allow if {
    some i
    input.card_id == data.bindings[i].card_id
    input.resource == data.bindings[i].resource
    input.action == data.bindings[i].action
    data.bindings[i].effect == "allow"
    not deny_exists
}
"""
    resp = opa_request("PUT", "/v1/policies/astralbench", rego, content_type="text/plain")
    print(f"Policy push: {json.dumps(resp)[:200]}")
    return "error" not in resp

def generate_bindings(num_cards):
    bindings = []
    for c in range(1, num_cards + 1):
        for r in range(10):
            for a in range(4):
                bindings.append({"card_id": f"card_{c}", "resource": f"res_{r}", "action": f"act_{a}", "effect": "allow", "priority": 40 - r})
        for r in range(5):
            bindings.append({"card_id": f"card_{c}", "resource": f"res_{r+10}", "action": f"act_{r%4}", "effect": "deny" if r % 3 == 0 else "allow", "priority": 5 - r})
    return bindings

def push_data(bindings):
    data = {"astralbench": {"bindings": bindings}}
    resp = opa_request("PUT", "/v1/data", data)
    if "error" in resp:
        print(f"  Push error: {resp['error'][:200]}")
    return "error" not in resp

def query_with_metrics(card_id, resource="res_0", action="act_0"):
    payload = {
        "input": {"card_id": card_id, "resource": resource, "action": action},
        "metrics": True
    }
    resp = opa_request("POST", "/v1/data/astralbench/allow", payload)
    result = resp.get("result")
    metrics = resp.get("metrics", {})
    eval_ns = metrics.get("timer_rego_query_eval_ns", -1)
    total_ns = metrics.get("timer_server_handler_ns", -1)
    return result, eval_ns, total_ns

def run_test(num_cards, num_iterations=10):
    print(f"\n  Generating {num_cards} cards x 45 rules = {num_cards*45} bindings...")
    bindings = generate_bindings(num_cards)

    print(f"  Pushing data to OPA...")
    ok = push_data(bindings)
    if not ok:
        print("  ERROR: Failed to push data!")
        return -1, -1

    print(f"  Warming up (50 iterations)...")
    for _ in range(50):
        query_with_metrics("card_1", "res_0", "act_0")

    print(f"\n  === Matching query (card_1, res_0, act_0) ===")
    eval_times = []
    for i in range(num_iterations):
        result, eval_ns, total_ns = query_with_metrics("card_1", "res_0", "act_0")
        eval_times.append(eval_ns)
        print(f"    iter {i+1:2d}: result={str(result):5s}, rego_eval={eval_ns:>10,}ns ({eval_ns/1000:>8.1f}us), total={total_ns:>10,}ns ({total_ns/1000:>8.1f}us)")

    avg_eval = sum(eval_times) / len(eval_times)
    print(f"    AVERAGE: rego_eval={avg_eval:,.0f}ns ({avg_eval/1000:.1f}us)")

    print(f"\n  === Non-matching query (card_99999, res_0, act_0) ===")
    miss_times = []
    for i in range(num_iterations):
        result, eval_ns, total_ns = query_with_metrics("card_99999", "res_0", "act_0")
        miss_times.append(eval_ns)
        print(f"    iter {i+1:2d}: result={str(result):5s}, rego_eval={eval_ns:>10,}ns ({eval_ns/1000:>8.1f}us), total={total_ns:>10,}ns ({total_ns/1000:>8.1f}us)")

    avg_miss = sum(miss_times) / len(miss_times)
    print(f"    AVERAGE: rego_eval={avg_miss:,.0f}ns ({avg_miss/1000:.1f}us)")

    return avg_eval, avg_miss

if __name__ == "__main__":
    print("=" * 70)
    print("OPA Index Verification Experiment")
    print("=" * 70)
    print()
    print("Hypothesis:")
    print("  If OPA builds index on card_id -> rego_eval ~ constant across data sizes")
    print("  If OPA does linear scan       -> rego_eval ~ 100x larger for 100x more data")
    print()

    ok = push_policy()
    if not ok:
        print("FATAL: Cannot push policy. Aborting.")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("Test A: 100 cards x 45 rules = 4,500 bindings")
    print("=" * 70)
    small_eval, small_miss = run_test(100, num_iterations=10)

    print("\n" + "=" * 70)
    print("Test B: 10000 cards x 45 rules = 450,000 bindings")
    print("=" * 70)
    large_eval, large_miss = run_test(10000, num_iterations=10)

    print("\n" + "=" * 70)
    print("VERDICT")
    print("=" * 70)
    if small_eval > 0 and large_eval > 0:
        ratio_eval = large_eval / small_eval
        ratio_miss = large_miss / small_miss if small_miss > 0 else 0
        print(f"  Matching query:  small={small_eval/1000:.1f}us, large={large_eval/1000:.1f}us, ratio={ratio_eval:.1f}x")
        print(f"  Miss query:      small={small_miss/1000:.1f}us, large={large_miss/1000:.1f}us, ratio={ratio_miss:.1f}x")
        print()
        if ratio_eval < 5:
            print("  CONCLUSION: OPA has implicit index - evaluation is O(rules_per_card)")
        elif ratio_eval > 50:
            print("  CONCLUSION: OPA does linear scan - evaluation is O(total_bindings)")
        else:
            print(f"  CONCLUSION: OPA has partial optimization - ratio={ratio_eval:.1f}x")
    else:
        print("  ERROR: Could not obtain valid measurements")
