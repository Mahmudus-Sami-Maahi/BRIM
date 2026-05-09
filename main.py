import os
import json
import time
from datetime import datetime
from agent.parser import APIParser
from agent.explorer import APIExplorer
from agent.tester import APITester
from agent.reporter import Reporter
from utils.auth import get_token, get_second_token

# Load environment variables from .env file (no external dependency)
def _load_env(path=".env"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())
    except FileNotFoundError:
        pass

_load_env()


def main():
    base_url = "https://backend-agent-test.onrender.com"
    spec_path = "openapi.json"
    start_time = datetime.utcnow()
    
    print("=" * 60)
    print("  Backend Testing Agent - Groq Powered")
    print("=" * 60)
    print(f"[*] Target: {base_url}")
    print(f"[*] Started at: {start_time.isoformat()}Z")
    print()

    # Open log file
    log_file = open("agent_log.txt", "w", encoding="utf-8")
    log_file.write(f"Agent Log - {start_time.isoformat()}Z\n")
    log_file.write(f"Target: {base_url}\n")
    log_file.write("=" * 60 + "\n\n")

    # ---- 1. Parse OpenAPI Spec ----
    print("[1/6] Parsing OpenAPI spec...")
    parser = APIParser(spec_path)
    endpoints = parser.parse()
    total_endpoints = len(endpoints)
    print(f"  Found {total_endpoints} endpoints")
    log_file.write(f"Parsed {total_endpoints} endpoints from {spec_path}\n\n")

    # ---- 2. Authenticate ----
    print("\n[2/6] Authenticating...")
    token, username, auth_findings = get_token(base_url)
    
    token2, username2 = get_second_token(base_url)
    if token2:
        print(f"  [*] Second user token obtained ({username2})")
    
    log_file.write(f"Auth: user1={username} (token={'yes' if token else 'no'})\n")
    log_file.write(f"Auth: user2={username2} (token={'yes' if token2 else 'no'})\n\n")

    # ---- 3. Setup real IDs ----
    print("\n[3/6] Setting up real resource IDs...")
    explorer = APIExplorer(base_url)
    tester = APITester(base_url, token=token, token2=token2, log_file=log_file)
    real_ids = tester.setup_real_ids()
    log_file.write(f"Real IDs: {real_ids}\n\n")

    all_findings = list(auth_findings)  # Start with auth findings

    # ---- 4. Generate & Run Tests ----
    print("\n[4/6] Running tests...")

    # Standard endpoint tests
    for i, endpoint in enumerate(endpoints):
        tests = explorer.generate_tests(endpoint, real_ids=real_ids)
        print(f"  [{i+1}/{total_endpoints}] {endpoint['method']} {endpoint['path']} ({len(tests)} tests)")
        results = tester.run(tests)
        for res in results:
            if "issues" in res and res["issues"]:
                all_findings.extend(res["issues"])

    # Special tests (rate limiting, business logic, CORS, endpoint probing)
    print("\n[5/6] Running special tests...")
    special_tests = explorer.generate_special_tests()

    # Replace {self_id} for follow-self test using real_ids
    self_user_id = real_ids.get("user_id")
    if self_user_id:
        for t in special_tests:
            if t.get("special") == "follow_self":
                t["path"] = f"/users/{self_user_id}/follow"
    elif token and username:
        import requests as req_lib
        try:
            me_res = req_lib.get(
                f"{base_url}/users/me",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            if me_res.status_code == 200:
                my_id = me_res.json().get("id")
                if my_id:
                    for t in special_tests:
                        if t.get("special") == "follow_self":
                            t["path"] = f"/users/{my_id}/follow"
        except:
            pass

    # Update double_like test with real post_id
    real_post_id = real_ids.get("post_id")
    if real_post_id:
        for t in special_tests:
            if t.get("special") == "double_like":
                t["path"] = f"/posts/{real_post_id}/like"

    results = tester.run(special_tests)
    for res in results:
        if "issues" in res and res["issues"]:
            all_findings.extend(res["issues"])

    # IDOR tests
    if token and token2:
        print("  Running IDOR/authorization tests...")
        idor_results = tester.run_idor_tests(real_ids=real_ids)
        for res in idor_results:
            if "issues" in res and res["issues"]:
                all_findings.extend(res["issues"])

    endpoints_tested = len(tester.endpoints_tested)
    print(f"\n  Total findings: {len(all_findings)}")
    print(f"  Endpoints tested: {endpoints_tested}/{total_endpoints}")

    # ---- 6. Generate Report ----
    print("\n[6/6] Generating report...")
    reporter = Reporter(
        base_url,
        all_findings,
        endpoints_tested=endpoints_tested,
        endpoints_total=total_endpoints,
        start_time=start_time
    )
    report = reporter.generate()

    # Validate against schema
    valid, error = Reporter.validate_report(report)
    if valid:
        print("  [✓] Report validates against schema")
    else:
        print(f"  [✗] Schema validation failed: {error}")

    # Write report
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    duration = (datetime.utcnow() - start_time).total_seconds()
    print(f"\n{'=' * 60}")
    print(f"  DONE in {duration:.1f}s")
    print(f"  Findings: {report['summary']['total']}")
    print(f"  By severity: {report['summary']['by_severity']}")
    print(f"  By category: {report['summary']['by_category']}")
    print(f"  Report: report.json")
    print(f"  Log:    agent_log.txt")
    print(f"{'=' * 60}")

    log_file.write(f"\n{'=' * 60}\n")
    log_file.write(f"Completed in {duration:.1f}s\n")
    log_file.write(f"Total findings: {report['summary']['total']}\n")
    log_file.close()

if __name__ == "__main__":
    main()
