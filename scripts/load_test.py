#!/usr/bin/env python3
"""Staging-only SentinelX enrollment + telemetry smoke/load test."""
import argparse
import concurrent.futures
import platform
import statistics
import time
import uuid

import requests


def run_one(index, base_url, bootstrap_token, verify):
    session = requests.Session()
    host = f"sentinelx-loadtest-{index:05d}"
    start = time.perf_counter()
    enrolled = session.post(
        f"{base_url}/api/v1/agents/enroll",
        json={
            "hostname": host,
            "os_name": "LoadTest",
            "machine_id": str(uuid.uuid4()),
        },
        headers={"X-Agent-Token": bootstrap_token},
        timeout=20,
        verify=verify,
    )
    enrolled.raise_for_status()
    credential = enrolled.json()
    sent = session.post(
        f"{base_url}/api/v1/telemetry",
        json={
            "host_id": credential["host_id"],
            "metrics": {
                "hostname": host,
                "platform": platform.platform(),
                "cpu_percent": 1.0,
                "memory": {"total_bytes": 1024, "available_bytes": 512, "percent": 50.0},
                "disk": {},
                "process_count": 1,
                "processes": [],
                "listening_ports": [],
                "load_test": True,
            },
            "events": [],
        },
        headers={"X-Agent-Token": credential["agent_token"]},
        timeout=20,
        verify=verify,
    )
    sent.raise_for_status()
    return time.perf_counter() - start


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Central API base URL, e.g. https://central:8443")
    parser.add_argument("--token", required=True, help="Enrollment/bootstrap token")
    parser.add_argument("--agents", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--ca", default=True, help="CA bundle path; use --insecure only for isolated testing")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification; isolated test environments only")
    args = parser.parse_args()
    if not 1 <= args.agents <= 10000 or not 1 <= args.concurrency <= 250:
        parser.error("agents must be 1..10000 and concurrency 1..250")

    verify = False if args.insecure else args.ca
    base_url = args.url.rstrip("/")
    print(f"WARNING: this creates {args.agents} persistent test agent registrations.")
    print("Run only against a staging SentinelX environment, not your production fleet.")
    started = time.perf_counter()
    durations = []
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {
            pool.submit(run_one, i, base_url, args.token, verify): i
            for i in range(1, args.agents + 1)
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                durations.append(future.result())
            except Exception as exc:
                failures.append((futures[future], str(exc)))

    elapsed = time.perf_counter() - started
    print(f"Agents requested: {args.agents}")
    print(f"Successful enroll + telemetry: {len(durations)}")
    print(f"Failures: {len(failures)}")
    print(f"Elapsed seconds: {elapsed:.2f}")
    print(f"Completed agents/sec: {len(durations) / elapsed:.2f}" if elapsed else "Completed agents/sec: n/a")
    if durations:
        print(f"Median per-agent seconds: {statistics.median(durations):.2f}")
        print(f"P95 per-agent seconds: {sorted(durations)[int(0.95 * (len(durations) - 1))]:.2f}")
    for index, message in failures[:20]:
        print(f"Failure {index}: {message}")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
