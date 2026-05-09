import uuid

class APIExplorer:
    def __init__(self, base_url):
        self.base_url = base_url

    def generate_tests(self, endpoint):
        path = endpoint["path"]
        method = endpoint["method"]

        # Replace path params with valid IDs
        resolved_path = path.replace("{user_id}", "1").replace("{post_id}", "1")

        tests = []

        # ---- 1. Valid request (with auth) ----
        tests.append({
            "name": "valid_auth",
            "method": method,
            "path": resolved_path,
            "data": self._valid_data(path, method),
            "auth": True
        })

        # ---- 2. No-auth test (test authentication enforcement) ----
        tests.append({
            "name": "no_auth",
            "method": method,
            "path": resolved_path,
            "data": self._valid_data(path, method),
            "auth": False
        })

        # ---- 3. Empty body (input validation) ----
        if method in ("POST", "PATCH", "PUT"):
            tests.append({
                "name": "empty_body",
                "method": method,
                "path": resolved_path,
                "data": {},
                "auth": True
            })

        # ---- 4. Bad input types ----
        if method in ("POST", "PATCH", "PUT"):
            tests.append({
                "name": "bad_types",
                "method": method,
                "path": resolved_path,
                "data": {"username": 12345, "password": True, "body": 999, "age": "not_a_number"},
                "auth": True
            })

        # ---- 5. Nonexistent resource (404 test) ----
        if "{post_id}" in path:
            tests.append({
                "name": "nonexistent_post",
                "method": method,
                "path": path.replace("{post_id}", "999999").replace("{user_id}", "1"),
                "data": self._valid_data(path, method),
                "auth": True
            })
        if "{user_id}" in path:
            tests.append({
                "name": "nonexistent_user",
                "method": method,
                "path": path.replace("{user_id}", "999999").replace("{post_id}", "1"),
                "data": self._valid_data(path, method),
                "auth": True
            })

        # ---- 6. Negative/zero ID (input validation) ----
        if "{post_id}" in path or "{user_id}" in path:
            tests.append({
                "name": "negative_id",
                "method": method,
                "path": path.replace("{user_id}", "-1").replace("{post_id}", "-1"),
                "data": self._valid_data(path, method),
                "auth": True
            })

        # ---- 7. HEAD request (http_protocol) ----
        if method == "GET":
            tests.append({
                "name": "head_request",
                "method": "HEAD",
                "path": resolved_path,
                "data": None,
                "auth": True
            })

        # ---- 8. OPTIONS request (http_protocol / CORS) ----
        if method == "GET":
            tests.append({
                "name": "options_request",
                "method": "OPTIONS",
                "path": resolved_path,
                "data": None,
                "auth": False
            })

        # ---- 9. SQL injection attempt (input validation) ----
        if method in ("POST", "PATCH", "PUT"):
            tests.append({
                "name": "sql_injection",
                "method": method,
                "path": resolved_path,
                "data": {"username": "' OR 1=1 --", "password": "' OR 1=1 --", "body": "'; DROP TABLE posts; --"},
                "auth": True
            })

        # ---- 10. XSS attempt (input validation) ----
        if method in ("POST", "PATCH", "PUT"):
            tests.append({
                "name": "xss_attempt",
                "method": method,
                "path": resolved_path,
                "data": {"body": "<script>alert('xss')</script>", "username": "<img onerror=alert(1) src=x>"},
                "auth": True
            })

        return tests

    def generate_special_tests(self):
        """Generate tests for specific bug categories that need custom logic."""
        tests = []

        # ---- Business Logic: follow yourself ----
        tests.append({
            "name": "follow_self",
            "method": "POST",
            "path": "/users/{self_id}/follow",  # Will be replaced with actual user ID
            "data": None,
            "auth": True,
            "special": "follow_self"
        })

        # ---- Business Logic: double like ----
        tests.append({
            "name": "double_like",
            "method": "POST",
            "path": "/posts/1/like",
            "data": None,
            "auth": True,
            "special": "double_like"
        })

        # ---- CORS: cross-origin request ----
        tests.append({
            "name": "cors_test",
            "method": "OPTIONS",
            "path": "/posts",
            "data": None,
            "auth": False,
            "headers": {"Origin": "http://evil.com", "Access-Control-Request-Method": "POST"},
            "special": "cors"
        })

        # ---- Rate limiting: burst test on login ----
        tests.append({
            "name": "rate_limit_login",
            "method": "POST",
            "path": "/auth/login",
            "data": {"username": "alice", "password": "wrong"},
            "auth": False,
            "special": "rate_limit",
            "burst_count": 20
        })

        # ---- Undocumented endpoints ----
        for probe_path in ["/admin", "/debug", "/health", "/metrics", "/api/v2", "/graphql", "/.env", "/swagger.json"]:
            tests.append({
                "name": f"probe_{probe_path.strip('/')}",
                "method": "GET",
                "path": probe_path,
                "data": None,
                "auth": False,
                "special": "endpoint_probe"
            })

        return tests

    def _valid_data(self, path, method):
        if method in ("GET", "DELETE", "HEAD", "OPTIONS"):
            return None
        if "register" in path:
            return {"username": f"user_{uuid.uuid4().hex[:6]}", "password": "test123"}
        if "login" in path:
            return {"username": "alice", "password": "alice123"}
        if "comments" in path:
            return {"body": "Nice post!"}
        if "posts" in path and method == "POST":
            return {"body": "Hello world from agent"}
        if "users/me" in path and method == "PATCH":
            return {"bio": "Updated bio", "age": 25}
        return {}