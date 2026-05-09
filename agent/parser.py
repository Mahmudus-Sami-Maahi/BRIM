import json

class APIParser:
    def __init__(self, spec_path):
        self.spec_path = spec_path

    def parse(self):
        with open(self.spec_path, "r", encoding="utf-8") as f:
            spec = json.load(f)

        # Store components for $ref resolution
        self.components = spec.get("components", {})

        endpoints = []
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                # Extract path parameter names
                path_params = []
                for param in details.get("parameters", []):
                    if param.get("in") == "path":
                        path_params.append(param["name"])

                # Extract request body JSON schema
                body_schema = None
                request_body = details.get("requestBody", {})
                if request_body:
                    content = request_body.get("content", {})
                    json_content = content.get("application/json", {})
                    schema = json_content.get("schema", None)
                    if schema:
                        body_schema = self._resolve_schema(schema)

                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": details.get("summary", ""),
                    "description": details.get("description", ""),
                    "parameters": details.get("parameters", []),
                    "requestBody": details.get("requestBody", {}),
                    "responses": details.get("responses", {}),
                    "path_params": path_params,
                    "body_schema": body_schema
                })
        return endpoints

    def _resolve_schema(self, schema):
        """Resolve $ref references in the schema."""
        if "$ref" in schema:
            ref_path = schema["$ref"]  # e.g. "#/components/schemas/CommentCreate"
            parts = ref_path.lstrip("#/").split("/")
            resolved = self.components
            for part in parts[1:]:  # skip 'components'
                resolved = resolved.get(part, {})
            return resolved
        return schema
