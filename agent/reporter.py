import json
import uuid
from datetime import datetime

class Reporter:
    def __init__(self, base_url, findings, endpoints_tested=0, endpoints_total=0, start_time=None):
        self.base_url = base_url
        self.findings = findings
        self.endpoints_tested = endpoints_tested
        self.endpoints_total = endpoints_total
        self.start_time = start_time or datetime.utcnow()

    def generate(self):
        """Generate the report conforming to report.schema.json."""
        seen_ids = set()
        unique_findings = []
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        category_counts = {}

        valid_categories = [
            "status_code", "schema_contract", "endpoint_existence",
            "input_validation", "authentication", "authorization",
            "error_handling", "headers_cors", "rate_limiting",
            "business_logic", "consistency", "performance",
            "documentation_drift", "http_protocol"
        ]
        valid_severities = ["critical", "high", "medium", "low"]
        valid_methods = ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS", "HEAD"]

        for f in self.findings:
            # Handle tuple/list findings from error handlers
            if isinstance(f, (tuple, list)):
                if len(f) >= 3:
                    f = {
                        "id": f"tuple-{uuid.uuid4().hex[:6]}",
                        "category": str(f[0]) if f[0] in valid_categories else "status_code",
                        "severity": str(f[1]) if f[1] in valid_severities else "low",
                        "title": str(f[2]),
                        "description": str(f[2]),
                        "endpoint": "/unknown",
                        "method": "GET"
                    }
                else:
                    continue

            if not isinstance(f, dict):
                continue

            # Generate unique ID
            fid = f.get("id", f.get("title", f"finding-{uuid.uuid4().hex[:6]}"))
            if isinstance(fid, str):
                fid = fid.lower().replace(" ", "-")[:80]
            else:
                fid = f"finding-{uuid.uuid4().hex[:6]}"
            
            if fid in seen_ids:
                fid = f"{fid}-{uuid.uuid4().hex[:4]}"
            seen_ids.add(fid)

            # Normalize all required fields
            f["id"] = fid

            # Category
            cat = f.get("category", "status_code")
            f["category"] = cat if cat in valid_categories else "status_code"

            # Severity
            sev = str(f.get("severity", "low")).lower()
            f["severity"] = sev if sev in valid_severities else "low"

            # Method
            method = str(f.get("method", "GET")).upper()
            f["method"] = method if method in valid_methods else "GET"

            # Endpoint
            endpoint = f.get("endpoint", "/unknown")
            if not isinstance(endpoint, str) or not endpoint:
                endpoint = "/unknown"
            f["endpoint"] = str(endpoint)

            # Title and description
            f["title"] = str(f.get("title", "Untitled finding"))[:200]
            if not f["title"]:
                f["title"] = "Untitled finding"
            f["description"] = str(f.get("description", f["title"]))
            if not f["description"]:
                f["description"] = f["title"]

            # Evidence
            evidence = f.get("evidence", {})
            if not isinstance(evidence, dict):
                evidence = {}
            if "request" not in evidence or not isinstance(evidence.get("request"), dict):
                evidence["request"] = {}
            if "response" not in evidence or not isinstance(evidence.get("response"), dict):
                evidence["response"] = {}
            f["evidence"] = evidence

            # Other required fields
            f["reproduction"] = str(f.get("reproduction", "N/A")) or "N/A"
            f["expected"] = str(f.get("expected", "N/A")) or "N/A"
            f["actual"] = str(f.get("actual", "N/A")) or "N/A"

            # Optional fields
            confidence = str(f.get("confidence", "medium")).lower()
            f["confidence"] = confidence if confidence in ["high", "medium", "low"] else "medium"

            if "suggested_fix" in f:
                f["suggested_fix"] = str(f["suggested_fix"])

            # Only keep schema-valid keys
            valid_keys = [
                "id", "category", "severity", "endpoint", "method",
                "title", "description", "evidence", "reproduction",
                "expected", "actual", "spec_reference", "confidence", "suggested_fix"
            ]
            f = {k: v for k, v in f.items() if k in valid_keys}

            unique_findings.append(f)
            severity_counts[f["severity"]] += 1
            category_counts[f["category"]] = category_counts.get(f["category"], 0) + 1

        duration = (datetime.utcnow() - self.start_time).total_seconds()
        coverage = (self.endpoints_tested / self.endpoints_total * 100) if self.endpoints_total > 0 else 0.0

        report = {
            "target": {
                "base_url": self.base_url,
                "tested_at": self.start_time.isoformat() + "Z",
                "spec_version": "1.0.0",
                "agent_name": "Groq-Agent",
                "duration_seconds": round(duration, 2)
            },
            "summary": {
                "total": len(unique_findings),
                "by_severity": severity_counts,
                "by_category": category_counts,
                "endpoints_tested": self.endpoints_tested,
                "endpoints_total": self.endpoints_total,
                "coverage_percent": round(coverage, 1)
            },
            "findings": unique_findings
        }

        return report

    @staticmethod
    def validate_report(report, schema_path="report.schema.json"):
        """Validate report against JSON schema."""
        try:
            import jsonschema
            with open(schema_path, "r", encoding="utf-8") as f:
                schema = json.load(f)
            jsonschema.validate(instance=report, schema=schema)
            return True, None
        except ImportError:
            print("[!] jsonschema not installed, skipping validation")
            return True, None
        except jsonschema.ValidationError as e:
            return False, str(e.message)
        except Exception as e:
            return False, str(e)
