import os, requests, re
port = os.environ.get('ORCH_PORT', '5001')
u = f'http://127.0.0.1:{port}/preview?target=http%3A%2F%2F127.0.0.1%3A{port}%2Fstatic%2Ftest_preview_ext.html'
t = requests.get(u).text
pattern_double = rf'=(\\s*)\"http://127\\.0\\.0\\.1:{port}/'
pattern_single = rf"='http://127\\.0\\.0\\.1:{port}/"
pattern_unquoted = rf"=(\\s*)http://127\\.0\\.0\\.1:{port}/"
print('abs_double:', bool(re.search(pattern_double, t)))
print('abs_single:', bool(re.search(pattern_single, t)))
print('abs_unquoted:', bool(re.search(pattern_unquoted, t)))
print('length:', len(t))
