#### **SENTINEL GATE: LAYER 7 DDOS MITIGATION AND TELEMETRY GATEWAY**



**Sentinel Gate is an advanced Layer 7 (L7) DDoS mitigation system designed specifically for FastAPI. It functions as a protective shield against application layer attacks that attempt to overwhelm server resources by spamming expensive API endpoints. By utilizing Redis for real time state monitoring and asynchronous telemetry, the system distinguishes between legitimate traffic and malicious botnet activity.**





##### **CORE TECHNICAL ARCHITECTURE:**



###### **A. LAYER 7 MITIGATION ENGINE:**

**Unlike Layer 4 firewalls that focus on packet counts, Sentinel Gate inspects the application layer to identify patterns used in L7 DDoS attacks. The system maintains a dynamic Blacklist in Redis. IPs identified as sources of L7 floods are blocked at the entry point. Sentinel Gate tracks the Request Weight. This prevents attackers from performing Low and Slow attacks or HTTP Floods against resource intensive paths like /search. To disrupt the timing of automated L7 attack scripts, the gateway introduces artificial processing delays. This increases the Cost of Attack for the botnet.**

###### 

###### **B. GEOGRAPHIC TELEMETRY AND FORENSICS:**

**The system captures deep metadata for every request to assist in post attack analysis and threat intelligence. Every L7 event is mapped to a physical location using httpx. This allows administrators to identify if a DDoS attack is originating from a specific geographic region. The logging process uses asyncio.create\_task to ensure that security overhead does not contribute to the very latency an attacker is trying to induce. Security events are recorded in access\_logs.json, providing a timeline of the attack progression.**



##### 

##### **TECHNICAL STACK:**



**The technical stack for Sentinel Gate is engineered for high concurrency and low latency defensive operations. At its core, FastAPI provides the high performance ASGI framework necessary for handling asynchronous request flows, while Redis serves as the primary "Security Brain," storing real time IP reputation and volumetric usage data in memory for sub-millisecond lookups. For external intelligence, the system utilizes HTTPX to perform non-blocking Geo IP resolution, ensuring that geographic telemetry is gathered without stalling the main application thread. Data persistence is managed via JSON Lines, creating a lightweight and append only forensic audit trail in access\_logs.json, and sensitive configuration is secured using Dotenv to manage environment variables like secret keys and database credentials.**





##### **SECURITY PHASES:**



**PHASE 1: The gateway checks Redis for banned IP. Known L7 attackers are served a 403 Forbidden status within microseconds.**



**PHASE 2: The system validates API keys. This ensures that legitimate VIP traffic is prioritized during an active DDoS event.**



**PHASE 3: The gateway calculates the strain on the backend. This is critical for stopping L7 attacks that target database heavy endpoints.**



**PHASE 4: If the L7 threshold is breached, the IP is Jailed, effectively dropping all subsequent traffic from that source.**





##### **FORENSIC LOG STRUCTURE:**



**The telemetry system generates standardized entries for L7 threat hunting:**



**{**

  **"timestamp": "YYYY-MM-DD HH:MM:SS",** 

  **"ip": "XXX.XXX.XXX.XXX",** 

  **"endpoint": "/PATH",** 

  **"status": 000,** 

  **"country": "COUNTRY\_NAME",** 

  **"city": "CITY\_NAME",** 

  **"lat": 00.00,** 

  **"lon": 00.00**

**}**





##### **SUPPORTING TOOLS:**



###### **A. BLACKLIST MANAGER (Blacklist\_Layer.py)**

**The administrative command center for the security system. Allows admins to permanently ban specific IP ranges. Functions to flush Redis counters and clear the "Jail" during maintenance or after a false-positive detection. Used to preload the database with known malicious IPs before an attack begins.**



###### **B. ATTACK SIMULATOR (Attack\_Simulator.py)**

**A high stress testing engine used to validate the L7 mitigation logic. Mimics a botnet by launching hundreds of asynchronous requests per second. Specifically spams the /search endpoint to prove that the gateway detects Expensive attacks faster than Light ones. Confirms that users with a valid X-API-KEY bypass standard limits even during a simulated DDoS event.**





##### 

##### **SETUP AND DEPLOYMENT:**



**Step 1: Define REDIS\_HOST, REDIS\_PORT, and VIP\_SECRET\_KEY within the .env file.**



**Step 2: Install requirements including redis, fastapi, uvicorn, httpx, and python-dotenv.**



**Step 3: Launch the gateway using Uvicorn. The system will automatically begin monitoring for L7 anomalies.**





