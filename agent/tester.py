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

    def setup_real_ids(self):
        """Create real resources and return a dictionary of real IDs for use in tests."""
        real_ids = {}

        if not self.token:
            return real_ids

        headers = {"Authorization": f"Bearer {self.token}"}

        # Get real user ID via GET /users/me
        try:
            res = requests.get(
                f"{self.base_url}/users/me",
                headers=headers,
                timeout=10
            )
            if res.status_code == 200:
                user_data = res.json()
                if user_data.get("id"):
                    real_ids["user_id"] = user_data["id"]
                    print(f"  [*] Real user_id: {real_ids['user_id']}")
        except Exception as e:
            print(f"  [!] Failed to get user ID: {e}")

        # Create a real post to get a real post_id
        try:
            res = requests.post(
                f"{self.base_url}/posts",
                json={"body": "Test post created by agent for testing"},
                headers=headers,
                timeout=10
            )
            if res.status_code in (200, 201):
                post_data = res.json()
                if post_data.get("id"):
                    real_ids["post_id"] = post_data["id"]
                    print(f"  [*] Real post_id: {real_ids['post_id']}")
        except Exception as e:
            print(f"  [!] Failed to create test post: {e}")

        return real_ids

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

                issues = self.detector.detect(test, res)

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

    def run_idor_tests(self, real_ids=None):
        """Test authorization: use token2 to edit/delete user1's resources."""
        results = []
        if not self.token2:
            return results

        if real_ids is None:
            real_ids = {}

        post_id = real_ids.get("post_id", 1)
        headers2 = {"Authorization": f"Bearer {self.token2}"}

        # IDOR Test 1: User2 tries to EDIT user1's post
        test_edit = {
            "name": "idor_edit_post",
            "method": "PATCH",
            "path": f"/posts/{post_id}",
            "data": {"body": "IDOR edit by user2"},
            "auth": True
        }
        try:
            res = requests.patch(
                f"{self.base_url}/posts/{post_id}",
                json={"body": "IDOR edit by user2"},
                headers=headers2,
                timeout=10
            )
            self._log_request(test_edit, res)
            issues = []
            if res.status_code == 200:
                issues.append({
                    "id": f"idor-edit-post-{post_id}",
                    "category": "authorization",
                    "severity": "high",
                    "endpoint": f"/posts/{post_id}",
                    "method": "PATCH",
                    "title": f"IDOR: User2 can edit User1's post {post_id}",
                    "description": f"User2 was able to edit post {post_id} owned by User1. The API returned 200 instead of 403.",
                    "evidence": {
                        "request": {"method": "PATCH", "url": f"/posts/{post_id}", "body": {"body": "IDOR edit by user2"}},
                        "response": {"status_code": res.status_code, "body": res.text[:500]}
                    },
                    "reproduction": f"PATCH /posts/{post_id} with User2's token",
                    "expected": "403 Forbidden",
                    "actual": f"{res.status_code} - resource was modified",
                    "confidence": "high",
                    "suggested_fix": "Verify resource ownership before allowing modifications"
                })
            results.append({"test": test_edit, "response": res, "issues": issues})
        except Exception as e:
            self._log_error(test_edit, str(e))

        # IDOR Test 2: User2 tries to DELETE user1's post
        test_delete = {
            "name": "idor_delete_post",
            "method": "DELETE",
            "path": f"/posts/{post_id}",
            "data": None,
            "auth": True
        }
        try:
            res = requests.delete(
                f"{self.base_url}/posts/{post_id}",
                headers=headers2,
                timeout=10
            )
            self._log_request(test_delete, res)
            issues = []
            if res.status_code == 200:
                issues.append({
                    "id": f"idor-delete-post-{post_id}",
                    "category": "authorization",
                    "severity": "high",
                    "endpoint": f"/posts/{post_id}",
                    "method": "DELETE",
                    "title": f"IDOR: User2 can delete User1's post {post_id}",
                    "description": f"User2 was able to delete post {post_id} owned by User1. The API returned 200 instead of 403.",
                    "evidence": {
                        "request": {"method": "DELETE", "url": f"/posts/{post_id}"},
                        "response": {"status_code": res.status_code, "body": res.text[:500]}
                    },
                    "reproduction": f"DELETE /posts/{post_id} with User2's token",
                    "expected": "403 Forbidden",
                    "actual": f"{res.status_code} - resource was deleted",
                    "confidence": "high",
                    "suggested_fix": "Verify resource ownership before allowing deletion"
                })
            results.append({"test": test_delete, "response": res, "issues": issues})
        except Exception as e:
            self._log_error(test_delete, str(e))

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
                    "description": f"Sent {burst_count} rapid requests to {test['path']} and none were rate-limited (no 429 status).",
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

            if res2.status_code in (200, 201):
                results.append({
                    "test": test,
                    "issues": [{
                        "id": "biz-double-like",
                        "category": "business_logic",
                        "severity": "medium",
                        "endpoint": test["path"],
                        "method": "POST",
                        "title": "Double-like allowed on post",
                        "description": "Liking the same post twice returns 200 both times.",
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
