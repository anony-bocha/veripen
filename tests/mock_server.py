from aiohttp import web
import re

async def handle_rce(request):
    """Simulates an authentic vulnerable endpoint executing bash commands."""
    data = await request.post()
    cmd = data.get("_method", "")
    
    # Check if the arithmetic verification challenge 'expr X + Y' is present
    match = re.search(r'expr\s+(\d+)\s*\+\s*(\d+)', cmd)
    if match:
        v1, v2 = int(match.group(1)), int(match.group(2))
        res = v1 + v2
        return web.Response(text=f"uid=0(root) gid=0(root)\n{res}\n")
    return web.Response(text="Standard response: no execution.")

async def handle_echo(request):
    """Simulates a classic exploitation hallucination: echoes input without execution."""
    query = request.query.get("query", "")
    return web.Response(text=f"<html><body>Search Results: {query}</body></html>", status=200)

app = web.Application()
app.router.add_post("/index.php", handle_rce)
app.router.add_get("/search", handle_echo)

if __name__ == "__main__":
    web.run_app(app, host="127.0.0.1", port=8080)
