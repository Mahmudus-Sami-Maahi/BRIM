import os
import json
import uuid
import traceback
import requests as req_lib

class IssueDetector:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        self.model = os.environ.get("MODEL_NAME", "meta-llama/llama-4-scout-17b-16e-instruct")
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"

    def is_suspicious(self, test, response):
        """Fast pre-check to determine if this response warrants AI analysis.
        Returns True if the response looks suspicious enough to call the AI."""
        # 500 status code = server error, always suspicious
        if response.status_code >= 500:
            return True

        # Protected endpoint returned 200 without auth
        if not test.get("auth", True) and response.status_code == 200:
            test_name = test.get("name", "")
            path = test.get("path", "")
            # Skip public endpoints that should return 200 without auth
            if test_name == "no_auth" and not any(pub in path for pub in ["/auth/login", "/auth/register", "/"]):
                return True

        # Auth endpoint returned 200 with wrong credentials
        test_name = test.get("name", "")
        if test_name in ("sql_injection", "xss_attempt", "bad_types"):
            path = test.get("path", "")
            if ("login" in path or "register" in path) and response.status_code == 200:
                return True

        # Check response body for error indicators
        try:
            body_lower = response.text[:3000].lower()
            for keyword in ("traceback", "exception", "stack"):
                if keyword in body_lower:
                    return True
        except:
            pass

        return False

    def detect(self, test, response):
        """Analyzes a requests.Response object using Groq REST API directly.
        Only calls the AI if the response is suspicious."""
        # Fast pre-check: skip AI for boring responses
        if not self.is_suspicious(test, response):
            return []

        try:
            req = response.request

            # Build request info
            body = None
            if req.body:
                if isinstance(req.body, bytes):
                    body = req.body.decode("utf-8", errors="replace")
                else:
                    body = str(req.body)

            request_info = json.dumps({
                "method": req.method,
                "url": str(req.url),
                "body": body
            }, indent=2)

            response_info = json.dumps({
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:1500]
            }, indent=2)

            prompt = f"""Analyze this API request/response for bugs across these 14 categories:
status_code, schema_contract, endpoint_existence, input_validation, authentication, authorization, error_handling, headers_cors, rate_limiting, business_logic, consistency, performance, documentation_drift, http_protocol.

REQUEST:
{request_info}

RESPONSE:
{response_info}

Return JSON: {{"findings": [  {{"category":"...","severity":"critical|high|medium|low","title":"...","description":"...","reproduction":"...","expected":"...","actual":"...","confidence":"high|medium|low","suggested_fix":"..."}}  ]}}
If no issues found, return {{"findings": []}}."""

            # Call Groq API directly via REST
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are an expert API security tester. Respond ONLY with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1,
                "response_format": {"type": "json_object"}
            }

            resp = req_lib.post(self.api_url, headers=headers, json=payload, timeout=30)
            resp.raise_for_status()

            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            result = json.loads(content)

            findings = result.get("findings", []) if isinstance(result, dict) else []

            # Normalize each finding
            for f in findings:
                if not isinstance(f, dict):
                    continue
                f["endpoint"] = req.path_url if hasattr(req, "path_url") else str(req.url)
                f["method"] = req.method
                if "id" not in f:
                    f["id"] = f"{f.get('category', 'bug')}-{uuid.uuid4().hex[:6]}"
                if "evidence" not in f:
                    f["evidence"] = {
                        "request": {"method": req.method, "url": str(req.url)},
                        "response": {"status_code": response.status_code}
                    }

            return [f for f in findings if isinstance(f, dict)]

        except Exception as e:
            print(f"[!] Groq API error: {e}")
            traceback.print_exc()
            return []