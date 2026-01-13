import redis            # High speed data store used for real time IP tracking and 'Jailing'
import asyncio          # Handles non blocking tasks (like adding delays or background logging)
from fastapi import FastAPI, Request  # The web framework and the tool to inspect incoming visitor data
from fastapi.responses import JSONResponse # Standard way to send back Banned or Success messages
import os               # Used to access system level settings like your .env file path
import json             # Formats your log data into a structured Dictionary for the database
from datetime import datetime # Stamps every security event with an exact date and time
import httpx            # An async browser used to call the Geo IP API without slowing the server
from dotenv import load_dotenv # Secret manager that hides your API keys and Redis passwords

# Initialize configuration and environment variables
load_dotenv()

# Setup Redis connection, it acts as our high-speed short term memory
# for tracking attackers and request counts in real-time.
r = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"), 
    port=int(os.getenv("REDIS_PORT", 6379)), 
    decode_responses=True
)

app = FastAPI()

# Endpoint Weights: Not all requests are equal. 
# A /search hit strains the database more than a simple / root hit, 
# so we charge attackers more for expensive routes.
ROUTE_WEIGHTS = {
    "/search": 5,
    "/data": 2,
    "/": 1
}

async def log_telemetry(ip, endpoint, status):
    """
    Forensic Logger: Runs in the background to capture geographic data.
    We use an external API to map the IP to a physical location.
    """
    try:
        # We set a 2-second timeout so that if the Geo-IP service is down,
        # it doesn't hang our background tasks.
        async with httpx.AsyncClient(timeout=2.0) as client:
            geo_response = await client.get(f"http://ip-api.com/json/{ip}")
            geo_data = geo_response.json()
        
        # Structure the log entry for easy parsing by tools like ELK or Splunk
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "endpoint": endpoint,
            "status": status,
            "country": geo_data.get("country", "Unknown"),
            "city": geo_data.get("city", "Unknown"),
            "lat": geo_data.get("lat", 0),
            "lon": geo_data.get("lon", 0)
        }
        
        # Append mode ensures we keep a permanent history of all security events
        with open("access_logs.json", "a") as f:
            f.write(json.dumps(entry) + "\n")
            
    except Exception as e:
        # Log the error but don't crash the gateway if logging fails
        print(f"Logging System Error: {e}")

@app.middleware("http")
async def security_gate_middleware(request: Request, call_next):
    """
    Main Security Middleware: Every request passes through these 5 phases.
    """
    client_ip = request.client.host
    endpoint = request.url.path
    
    # --- PHASE 1: REPUTATION CHECK ---
    # Check if the IP is already in our Jail list. Fastest check first to save CPU.
    if r.exists(f"banned:{client_ip}"):
        # Capture the attempt by the banned user for forensic evidence
        asyncio.create_task(log_telemetry(client_ip, endpoint, 403))
        return JSONResponse(status_code=403, content={"msg": "STILL BANNED"})

    # --- PHASE 2: IDENTITY & LIMITS ---
    # Give higher limits to VIP users (API Key holders) while keeping guest limits low.
    api_key = request.headers.get("x-api-key")
    limit = 50 if api_key == os.getenv("VIP_SECRET_KEY") else 10
    
    # --- PHASE 3: ATOMIC RATE LIMITING ---
    # Calculate the cost of the requested route and update usage in Redis.
    weight = ROUTE_WEIGHTS.get(endpoint, 1)
    current_usage = r.incrby(f"usage:{client_ip}", weight)
    
    # If this is the first request in the window, set the 20 second countdown.
    if current_usage == weight:
        r.expire(f"usage:{client_ip}", 20)

    # --- PHASE 4: MITIGATION (The "Brakes") ---
    # If the user is at 50% capacity, inject a 1 second 
    # delay to frustrate botnets and slow down their attack.
    if current_usage > (limit / 2):
        await asyncio.sleep(1) 

    # If they cross the limit, issue a 30 second ban.
    if current_usage > limit:
        r.setex(f"banned:{client_ip}", 30, "true")
        asyncio.create_task(log_telemetry(client_ip, endpoint, 429))
        return JSONResponse(status_code=429, content={"msg": "LIMIT EXCEEDED"})

    # --- PHASE 5: SUCCESS PATH ---
    # If they passed all checks, proceed to the actual API endpoint.
    response = await call_next(request)
    
    # We trigger the logger as a background task
    # so the user gets their data immediately without waiting for file I/O.
    asyncio.create_task(log_telemetry(client_ip, endpoint, response.status_code))
    
    # Return the response to the client
    return response

# --- API ENDPOINTS ---

@app.get("/search")
async def search():
    """Mock database search endpoint."""
    return {"result": "Search results found"}

@app.get("/")
async def root():
    """Health check endpoint to verify the gateway is active."""
    return {"status": "Sentinel-Gate Active", "secure": True}