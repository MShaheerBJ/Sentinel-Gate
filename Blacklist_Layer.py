import redis
import time

# 1. THE CONNECTION (With Error Handling)
try:
    r = redis.Redis(host='localhost', port=6379, decode_responses=True)
    r.ping() # Test the heart
except Exception:
    print("🚨 CRITICAL: Redis is down. System entering FAIL-CLOSED mode.")
    r = None

def professional_security_gate(ip, api_key=None):
    # Fail-Closed Check
    if r is None:
        return "❌ SYSTEM ERROR: Security Gate is locked for maintenance."

    # Permanent Blocklist Check (The 'Jail')
    if r.exists(f"banned:{ip}"):
        return f"🛑 BANNED: Your IP is in jail for {r.ttl(f'banned:{ip}')}s"

    # Identity Hierarchy (Key vs IP)
    # If they have a key, we track the key. If not, we track the IP.
    identifier = api_key if api_key else ip
    
    # The Increment & Expiry
    try:
        count = r.incr(f"rate:{identifier}")
        if count == 1:
            r.expire(f"rate:{identifier}", 60) # Reset every minute

        if count > 10: # More generous for the "Pro" gate
            r.setex(f"banned:{ip}", 300, "true") # Ban for 5 minutes
            return "❌ ABUSE DETECTED: IP Banned for 5 minutes."
            
        return f"✅ Request {count}/10 Allowed for {identifier}"
    
    except Exception as e:
        return "❌ SECURITY ERROR: Could not verify identity."

# --- TESTING THE PRO GATE ---
print(professional_security_gate("127.0.0.1", api_key="PREMIUM_USER_123"))
print(professional_security_gate("127.0.0.1")) # No key (Suspicious)