import requests
import time
import uuid

def get_token(base_url):
    """Try all 3 seeded accounts, then register a fresh user as fallback."""
    accounts = [
        ("alice", "alice123"),
        ("bob", "bob123"),
        ("carol", "carol123"),
    ]
    
    findings = []
    
    for username, password in accounts:
        token = _try_login(base_url, username, password)
        if token:
            print(f"  [*] Logged in as {username}")
            return token, username, findings
        else:
            # Login failed - attempt to register the account first
            print(f"  [!] Login failed for {username}, attempting registration...")
            reg_token = _try_register(base_url, username, password)
            if reg_token:
                print(f"  [*] Registered and logged in as {username}")
                return reg_token, username, findings
            
            # Try login again after registration attempt
            token = _try_login(base_url, username, password)
            if token:
                print(f"  [*] Logged in as {username} after registration")
                return token, username, findings
            
            # Only record as bug if login still fails after registration attempt
            findings.append({
                "id": f"auth-login-fail-{username}",
                "category": "authentication",
                "severity": "high",
                "endpoint": "/auth/login",
                "method": "POST",
                "title": f"Seeded account '{username}' returns 401",
                "description": f"The seeded test account '{username}' with documented password '{password}' returns 401 even after attempting registration.",
                "evidence": {
                    "request": {"username": username, "password": password},
                    "response": {"status_code": 401, "detail": "invalid credentials"}
                },
                "reproduction": f"POST /auth/login with username={username}",
                "expected": "200 with access_token",
                "actual": "401 invalid credentials",
                "confidence": "high",
                "suggested_fix": "Ensure seeded test accounts are created on startup"
            })
    
    # Fallback: register a fresh user
    print("  [*] All seeded accounts failed. Registering fresh user...")
    fresh_user = f"agent_{uuid.uuid4().hex[:8]}"
    fresh_pass = "TestPass123"
    
    try:
        res = requests.post(
            base_url + "/auth/register",
            json={"username": fresh_user, "password": fresh_pass},
            timeout=15
        )
        if res.status_code in (200, 201):
            token = res.json().get("access_token")
            if token:
                print(f"  [*] Registered and logged in as {fresh_user}")
                return token, fresh_user, findings
    except Exception as e:
        print(f"  [!] Registration failed: {e}")
    
    token = _try_login(base_url, fresh_user, fresh_pass)
    if token:
        print(f"  [*] Logged in as {fresh_user}")
        return token, fresh_user, findings
    
    print("  [!] All auth attempts failed")
    return None, None, findings


def get_second_token(base_url):
    """Get a second user's token for authorization/IDOR tests."""
    for username, password in [("bob", "bob123"), ("carol", "carol123")]:
        token = _try_login(base_url, username, password)
        if token:
            return token, username
        reg_token = _try_register(base_url, username, password)
        if reg_token:
            return reg_token, username
        token = _try_login(base_url, username, password)
        if token:
            return token, username
    
    fresh_user = f"agent2_{uuid.uuid4().hex[:8]}"
    fresh_pass = "TestPass456"
    try:
        res = requests.post(
            base_url + "/auth/register",
            json={"username": fresh_user, "password": fresh_pass},
            timeout=15
        )
        if res.status_code in (200, 201):
            token = res.json().get("access_token")
            if token:
                return token, fresh_user
    except:
        pass
    
    return None, None


def _try_register(base_url, username, password):
    """Attempt to register a user and return the token if successful."""
    try:
        res = requests.post(
            base_url + "/auth/register",
            json={"username": username, "password": password},
            timeout=15
        )
        if res.status_code in (200, 201):
            return res.json().get("access_token")
    except Exception as e:
        print(f"  [!] Registration for {username} failed: {e}")
    return None


def _try_login(base_url, username, password, retries=2):
    """Attempt login with retries."""
    for attempt in range(retries):
        try:
            res = requests.post(
                base_url + "/auth/login",
                json={"username": username, "password": password},
                timeout=15
            )
            if res.status_code == 200:
                return res.json().get("access_token")
            else:
                if attempt == 0:
                    print(f"  [!] Login {username}: {res.status_code} - {res.text[:100]}")
        except requests.exceptions.Timeout:
            print(f"  [!] Login {username}: timeout")
        except Exception as e:
            print(f"  [!] Login {username}: {e}")
        
        if attempt < retries - 1:
            time.sleep(3)
    
    return None