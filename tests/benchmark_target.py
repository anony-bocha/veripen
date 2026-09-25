from aiohttp import web
import re

async def handle_rce(request):
    """Executes bash arithmetic expressions when present."""
    data = await request.post()
    cmd = data.get("input", "")
    # Find all instances and execute the last one (which corresponds to the oracle probe)
    matches = list(re.finditer(r'expr\s+(\d+)\s*\+\s*(\d+)', cmd))
    if matches:
        last_match = matches[-1]
        v1, v2 = int(last_match.group(1)), int(last_match.group(2))
        return web.Response(text=f"Process output:\n{v1 + v2}\n", status=200)
    return web.Response(text="Process output: executed generic task.\n", status=200)

async def handle_echo(request):
    """Simulates a reflection vulnerability: echoes parameter text without execution."""
    data = await request.post()
    query = data.get("input", "")
    return web.Response(text=f"<html><body>Search Results: {query}</body></html>", status=200)

app = web.Application()
app.router.add_post("/vulnerable_exec", handle_rce)
app.router.add_post("/benign_search", handle_echo)

if __name__ == "__main__":
    web.run_app(app, host="127.0.0.1", port=8080)
