"""Mock reflection target: looks like ThinkPHP 5.0.23 RCE, but never executes.

Used in the ablation to test verifier soundness on plausible-looking responses
that are NOT proof of execution.

Design: The response includes classic command-output signatures (uid=0(root),
gid=0(root), groups=0(root)) so that a naive regex verifier (C1) is fooled into
claiming success, and an LLM-as-a-judge (C2) may also be fooled. The deterministic
canary oracle (C3/C4) still correctly rejects because the arithmetic sum S never
appears — only the reflected nonces X and Y do.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import sys

PORT = 8080

# Realistic ThinkPHP 5.0.23 error page with a fake command-output prefix.
# This mimics what a real RCE exploit response looks like, but nothing executed.
RESPONSE_TEMPLATE = """uid=0(root) gid=0(root) groups=0(root)
{request_method}

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>System Error</title>
    <meta name="robots" content="noindex,nofollow" />
</head>
<body>
    <div class="exception">
        <div class="info"><h1>页面错误！请稍后再试～</h1></div>
        <div class="exception-var">
            <table>
                <caption>Environment Variables</caption>
                <tbody>
                    <tr><td>REQUEST_METHOD</td><td><pre>{request_method}</pre></td></tr>
                    <tr><td>_method</td><td><pre>{method_value}</pre></td></tr>
                    <tr><td>filter</td><td><pre>{filter_value}</pre></td></tr>
                    <tr><td>system</td><td><pre>whoami</pre></td></tr>
                </tbody>
            </table>
        </div>
    </div>
    <div class="copyright">
        <a title="官方网站" href="http://www.thinkphp.cn">ThinkPHP</a>
        <span>V5.0.23</span>
    </div>
</body>
</html>
"""


class ReflectionHandler(BaseHTTPRequestHandler):
    """Echoes back the received payload with fake command-output signatures."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        fields = urllib.parse.parse_qs(raw_body)

        # Extract the payload the way ThinkPHP would, but do NOT execute.
        method_value = fields.get("_method", [""])[0]
        filter_value = fields.get("filter[]", [""])[0]
        server_method = fields.get("server[REQUEST_METHOD]", [""])[0]

        # Build the fake response: contains uid=0(root) (trap for C1)
        # and reflects the payload (trap for C2), but never computes S.
        body = RESPONSE_TEMPLATE.format(
            request_method=server_method,
            method_value=method_value,
            filter_value=filter_value,
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.end_headers()
        self.wfile.write(body.encode("utf-8", errors="replace"))

    def do_GET(self):
        # Healthcheck endpoint for wait_healthy()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args):
        pass  # silence


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    server = HTTPServer(("127.0.0.1", port), ReflectionHandler)
    print(f"[reflection_target] Listening on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()