import uuid

class APIExplorer:
    def __init__(self, base_url):
        self.base_url = base_url

    def generate_tests(self, endpoint, real_ids=None):
        path = endpoint["path"]
        method = endpoint["method"]
        path_params = endpoint.get("path_params", [])
        body_schema = endpoint.get("body_schema", None)

        if real_ids is None:
            real_ids = {}

        # Replace path params dynamically using real_ids
        resolved_path = self._resolve_path(path, path_params, real_ids)

        tests = []

        # ---- 1. Valid request (with auth) ----
        tests.append({
            "name": "valid_auth",
            "method": method,
            "path": resolved_path,
            "data": self._valid_data_from_schema(body_schema, path, method),
            "auth": True
        })

        # ---- 2. No-auth test (test authentication enforcement) ----
        tests.append({
            "name": "no_auth",
            "method": method,
            "path": resolved_path,
            "data": self._valid_data_from_schema(body_schema, path, method),
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
        for param in path_params:
            tests.append({
                "name": f"nonexistent_{param}",
                "method": method,
                "path": self._resolve_path(path, path_params, {**real_ids, param: "999999"}),
                "data": self._valid_data_from_schema(body_schema, path, method),
                "auth": True
            })

        # ---- 6. Negative/zero ID (input validation) ----
        if path_params:
            negative_ids = {p: "-1" for p in path_params}
            tests.append({
                "name": "negative_id",
                "method": method,
                "path": self._resolve_path(path, path_params, negative_ids),
                "data": self._valid_data_from_schema(body_schema, path, method),
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
            "path": "/users/{user_id}/follow",  # Will be replaced with actual user ID
            "data": None,
            "auth": True,
            "special": "follow_self"
        })

        # ---- Business Logic: double like ----
        tests.append({
            "name": "double_like",
            "method": "POST",
            "path": "/posts/{post_id}/like",
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

    def _resolve_path(self, path, path_params, real_ids):
        """Dynamically replace all path parameters with values from real_ids.
        Falls back to '1' if no real ID is available for a parameter."""
        resolved = path
        for param in path_params:
            placeholder = "{" + param + "}"
            value = str(real_ids.get(param, "1"))
            resolved = resolved.replace(placeholder, value)
        return resolved

    def _valid_data_from_schema(self, body_schema, path, method):
        """Generate valid sample data dynamically from the body_schema.
        Falls back to None for methods that don't send bodies."""
        if method in ("GET", "DELETE", "HEAD", "OPTIONS"):
            return None

        if not body_schema or not isinstance(body_schema, dict):
            return {}

        properties = body_schema.get("properties", {})
        if not properties:
            return {}

        data = {}
        for field_name, field_def in properties.items():
            field_type = self._get_type(field_def)
            if field_type == "string":
                data[field_name] = f"test_{field_name}"
            elif field_type == "integer":
                data[field_name] = 1
            elif field_type == "number":
                data[field_name] = 1.0
            elif field_type == "boolean":
                data[field_name] = True
            elif field_type == "array":
                data[field_name] = []
            elif field_type == "object":
                data[field_name] = {}
            else:
                data[field_name] = f"test_{field_name}"

        return data

    def _get_type(self, field_def):
        """Extract the type from a field definition, handling anyOf/oneOf."""
        if "type" in field_def:
            return field_def["type"]
        # Handle anyOf (e.g., nullable fields)
        for key in ("anyOf", "oneOf"):
            if key in field_def:
                for option in field_def[key]:
                    if option.get("type") and option["type"] != "null":
                        return option["type"]
        return "string"