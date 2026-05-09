import requests
import time
import json
from agent.detectors import IssueDetector

class APITester:
    def __init__(self, base_url, token=None, token2=None, log_file=None):
        self.base_url = base_url
        self.token = token
        self.token2 = token2  # Second user token for IDOR tests
        self.detector = IssueDetector()
        self.log_file = log_file
        self.endpoints_tested = set()

    def run(self, tests):
        results = []

        for test in tests:
            special = test.get("special")

            # Handle special tests
            if special == "rate_limit":
                results.extend(self._run_rate_limit_test(test))
                continue
            if special == "double_like":
                results.extend(self._run_double_like_test(test))
                continue

            url = self.base_url + test["path"]
            use_auth = test.get("auth", True)

            headers = {}
            if use_auth and self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            
            # Add any custom headers
            if "headers" in test:
                headers.update(test["headers"])

            try:
                data = test.get("data")
                kwargs = {
                    "method": test["method"],
                    "url": url,
                    "headers": headers,
                    "timeout": 10
                }
                if data is not None:
                    kwargs["json"] = data

                res = requests.request(**kwargs)
                self.endpoints_tested.add(test["path"])
                self._log_request(test, res)

                issues = self.detector.detect(res)

                results.append({
                    "test": test,
                    "response": res,
                    "issues": issues
                })

            except requests.exceptions.Timeout:
                self._log_error(test, "Timeout")
                results.append({
                    "test": test,
                    "error": "Timeout",
                    "issues": [{
                        "id": f"perf-timeout-{test['path'].replace('/', '-')}",
                        "category": "performance",
                        "severity": "high",
                        "endpoint": test["path"],
                        "method": test["method"],
                        "title": f"Request timeout on {test['method']} {test['path']}",
                        "description": f"Request to {test['method']} {test['path']} timed out after 10 seconds",
                        "evidence": {"request": {"method": test["method"], "url": url}, "response": {"error": "timeout"}},
                        "reproduction": f"Send {test['method']} to {url}",
                        "expected": "Response within 10 seconds",
                        "actual": "Request timed out",
                        "confidence": "high"
                    }]
                })
            except Exception as e:
                self._log_error(test, str(e))
                results.append({
                    "test": test,
                    "error": str(e),
                    "issues": []
                })

        return results

    def run_idor_tests(self, user1_id):
        """Test authorization: use token2 to access user1's resources."""
        results = []
        if not self.token2:
            return results

        # Try to update user1's profile with user2's token
        test = {
            "name": "idor_update_profile",
            "method": "PATCH",
            "path": "/users/me",
            "data": {"bio": "IDOR test"},
            "auth": True
        }
        headers = {"Authorization": f"Bearer {self.token2}"}
        try:
            res = requests.patch(
                f"{self.base_url}/users/me",
                json={"bio": "IDOR test"},
                headers=headers,
                timeout=10
            )
            self._log_request(test, res)
            issues = self.detector.detect(res)
            results.append({"test": test, "response": res, "issues": issues})
        except:
            pass

        return results

    def _run_rate_limit_test(self, test):
        """Send a burst of requests to test rate limiting."""
        results = []
        url = self.base_url + test["path"]
        burst_count = test.get("burst_count", 20)
        
        statuses = []
        for i in range(burst_count):
            try:
                res = requests.post(url, json=test.get("data", {}), timeout=5)
                statuses.append(res.status_code)
            except:
                statuses.append(0)
        
        # If all requests succeeded (no 429), that's a finding
        rate_limited = any(s == 429 for s in statuses)
        if not rate_limited:
            results.append({
                "test": test,
                "issues": [{
                    "id": "rate-limit-missing-login",
                    "category": "rate_limiting",
                    "severity": "high",
                    "endpoint": test["path"],
                    "method": test["method"],
                    "title": f"No rate limiting on {test['path']}",
                    "description": f"Sent {burst_count} rapid requests to {test['path']} and none were rate-limited (no 429 status). This allows brute-force attacks.",
                    "evidence": {
                        "request": {"burst_count": burst_count, "url": url},
                        "response": {"statuses": statuses[:10]}
                    },
                    "reproduction": f"Send {burst_count} rapid POST requests to {url}",
                    "expected": "429 Too Many Requests after several attempts",
                    "actual": f"All {burst_count} requests returned non-429 statuses: {set(statuses)}",
                    "confidence": "high",
                    "suggested_fix": "Implement rate limiting on sensitive endpoints"
                }]
            })
        
        self._log_line(f"RATE_LIMIT {test['path']}: {burst_count} requests, statuses={set(statuses)}, rate_limited={rate_limited}")
        return results

    def _run_double_like_test(self, test):
        """Test business logic: like a post twice."""
        results = []
        if not self.token:
            return results

        url = self.base_url + test["path"]
        headers = {"Authorization": f"Bearer {self.token}"}

        try:
            # Like once
            res1 = requests.post(url, headers=headers, timeout=10)
            # Like again (should fail or be idempotent)
            res2 = requests.post(url, headers=headers, timeout=10)

            if res2.status_code == 200:
                results.append({
                    "test": test,
                    "issues": [{
                        "id": "biz-double-like",
                        "category": "business_logic",
                        "severity": "medium",
                        "endpoint": test["path"],
                        "method": "POST",
                        "title": "Double-like allowed on post",
                        "description": "Liking the same post twice returns 200 both times. The API should reject duplicate likes or return a different status.",
                        "evidence": {
                            "request": {"url": url, "action": "POST twice"},
                            "response": {"first_status": res1.status_code, "second_status": res2.status_code}
                        },
                        "reproduction": f"POST {url} twice with same auth token",
                        "expected": "Second like should return 409 or 400",
                        "actual": f"Second like returned {res2.status_code}",
                        "confidence": "high",
                        "suggested_fix": "Return 409 Conflict when user has already liked the post"
                    }]
                })
            
            # Unlike to clean up
            requests.delete(url, headers=headers, timeout=10)
        except:
            pass

        return results

    def _log_request(self, test, response):
        """Log request/response to agent_log.txt."""
        line = f"{test['method']} {test['path']} [{test.get('name', '')}] => {response.status_code} ({len(response.content)} bytes)"
        self._log_line(line)

    def _log_error(self, test, error):
        line = f"{test['method']} {test['path']} [{test.get('name', '')}] => ERROR: {error}"
        self._log_line(line)

    def _log_line(self, line):
        if self.log_file:
            try:
                self.log_file.write(line + "\n")
                self.log_file.flush()
            except:
                pass
