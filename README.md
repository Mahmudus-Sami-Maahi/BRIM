# 🚀 Backend Testing Agent

An AI-powered agent designed to perform **automated black-box testing** on a live REST API using its OpenAPI specification.

This project demonstrates how intelligent agents can explore APIs, detect inconsistencies, and generate structured bug reports — with minimal human intervention.

---

## 📌 Overview

The **Backend Testing Agent** takes an API as input and autonomously:

* Explores endpoints
* Sends structured and edge-case requests
* Detects unexpected behaviors
* Generates a standardized bug report

The output is a single file:

```
report.json
```

which summarizes all discovered issues.

---

## ⚙️ Inputs

The agent works with the following inputs:

* **Base URL**
  `https://backend-agent-test.onrender.com`

* **OpenAPI Spec**
  Describes all endpoints and expected schemas

* **Authentication Credentials**

  ```
  alice / alice123
  bob / bob123
  carol / carol123
  ```

### 🔐 Authentication

Login endpoint:

```
POST /auth/login
```

Request:

```json
{
  "username": "alice",
  "password": "alice123"
}
```

Response:

```json
{
  "access_token": "..."
}
```

Use the token in requests:

```
Authorization: Bearer <token>
```

---

## 🧠 What the Agent Does

The agent is designed to be **autonomous and reproducible**.

### Core Capabilities

* Parses the OpenAPI specification
* Discovers available endpoints
* Generates valid and invalid test cases
* Sends API requests and analyzes responses
* Detects inconsistencies, errors, and vulnerabilities
* Produces a structured report

Running the agent multiple times should yield consistent results (except minor timing differences).

---

## 🐞 Bug Categories

The agent detects issues across multiple dimensions:

* **Status Code Issues** – Incorrect HTTP responses
* **Schema Mismatch** – Response doesn’t match spec
* **Missing/Extra Endpoints**
* **Input Validation Failures**
* **Authentication Issues**
* **Authorization Problems (IDOR, privilege escalation)**
* **Error Handling Leaks**
* **Headers & CORS Misconfigurations**
* **Rate Limiting Weaknesses**
* **Business Logic Flaws**
* **Data Consistency Issues**
* **Performance Problems**
* **Documentation Drift**
* **HTTP Protocol Issues**

---

## 📊 Output

### `report.json`

The final output:

* Must follow the provided schema
* Contains all detected issues
* Includes reproducible findings

Example structure:

```json
{
  "findings": [
    {
      "category": "status_code",
      "endpoint": "/example",
      "issue": "Expected 200 but got 500"
    }
  ]
}
```

---

## 📁 Project Structure

```
.
├── agent/              # Your testing agent implementation
├── openapi.json        # API specification
├── report.schema.json  # Output validation schema
├── report.json         # Generated report
└── README.md
```

---

## 🛠️ How to Run

1. Clone the repository
2. Install dependencies
3. Run the agent

Example:

```
python main.py
```

After execution, check:

```
report.json
```

---

## 🧪 Best Practices

* Use dynamic data (avoid hardcoding IDs)
* Respect API limits (no heavy load testing)
* Handle state changes carefully (DELETE/PATCH modify data)
* Ensure repeatability of results

---

## 🌐 Notes

* The API state may reset periodically
* Multiple users may interact with the same API
* Prefer discovery over assumptions

---

## 🤝 Contribution

Feel free to improve:

* Test coverage
* Bug detection logic
* Performance optimization
* Reporting clarity

---

## 💡 Vision

This project is a step toward fully autonomous QA systems — where AI agents can test, validate, and improve backend systems continuously.

---

**Build smarter. Test faster. Ship with confidence. 🚀**
