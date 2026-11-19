from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import json
from analyzer import analyze_csv

ROOT = Path(__file__).resolve().parent
class Handler(BaseHTTPRequestHandler):
    def send_bytes(self, status, content, content_type):
        self.send_response(status); self.send_header('Content-Type', content_type); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(content)
    def do_GET(self):
        if self.path == '/api/sample':
            return self.send_bytes(200, (ROOT/'sample_events.csv').read_bytes(), 'text/csv; charset=utf-8')
        if self.path in ('/', '/index.html'):
            return self.send_bytes(200, (ROOT/'index.html').read_bytes(), 'text/html; charset=utf-8')
        return self.send_bytes(404, b'Not found', 'text/plain')
    def do_POST(self):
        if self.path != '/api/analyze': return self.send_bytes(404,b'Not found','text/plain')
        try:
            length = int(self.headers.get('Content-Length','0'))
            if length <= 0 or length > 2_000_000: raise ValueError('Upload must be between 1 byte and 2 MB.')
            text = self.rfile.read(length).decode('utf-8-sig')
            result = analyze_csv(text)
            clean = [{k:v for k,v in e.items() if not k.startswith('_')} for e in result['events']]
            result['events'] = clean
            return self.send_bytes(200, json.dumps(result).encode(), 'application/json; charset=utf-8')
        except (ValueError, UnicodeDecodeError) as exc:
            return self.send_bytes(400, json.dumps({'error':str(exc)}).encode(), 'application/json; charset=utf-8')
    def log_message(self, *_): pass

if __name__ == '__main__':
    print('GhostTrail running at http://127.0.0.1:8765 (local only). Ctrl+C to stop.')
    HTTPServer(('127.0.0.1',8765), Handler).serve_forever()
