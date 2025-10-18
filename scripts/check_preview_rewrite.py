import os, re
import requests

port = os.environ.get('ORCH_PORT', '5001')
u = f'http://127.0.0.1:{port}/preview?target=http://127.0.0.1:{port}/static/test_preview_ext.html'
r = requests.get(u)
print('status', r.status_code)
text = r.text
m = re.search(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\']([^"\']+)["\']', text, flags=re.I)
print('refresh', m.group(1) if m else 'none')
print('base tag present', bool(re.search(r'<base ', text, flags=re.I)))
print('contains local origin', f'http://127.0.0.1:{port}' in text)
