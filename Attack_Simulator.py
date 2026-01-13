import asyncio
import httpx
import time

TARGET_URL = "http://127.0.0.1:8000/search"

async def simulate_bot(bot_id):
    async with httpx.AsyncClient() as client:
        for i in range(15):
            try:
                start_time = time.time()
                # We must await the get request
                response = await client.get(TARGET_URL) 
                duration = time.time() - start_time
                
                print(f"Bot {bot_id} | Req {i} | Status: {response.status_code} | Time: {duration:.2f}s")
                
                if response.status_code == 403:
                    print(f"❌ Bot {bot_id} is officially JAILED.")
                    break
            except Exception as e:
                print(f"Bot {bot_id} failed: {str(e)}")
            
            await asyncio.sleep(0.1)

async def main():
    print("🚀 LAUNCHING ATTACK SIMULATION...")
    bots = [simulate_bot(i) for i in range(5)]
    await asyncio.gather(*bots)

if __name__ == "__main__":
    asyncio.run(main())