import json

class APIParser:
    def __init__(self, spec_path):
        self.spec_path = spec_path

    def parse(self):
        with open(self.spec_path, "r", encoding="utf-8") as f:
            spec = json.load(f)
        
        endpoints = []
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": details.get("summary", ""),
                    "description": details.get("description", ""),
                    "parameters": details.get("parameters", []),
                    "requestBody": details.get("requestBody", {}),
                    "responses": details.get("responses", {})
                })
        return endpoints
