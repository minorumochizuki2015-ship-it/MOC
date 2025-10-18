import os, requests
port = os.environ.get('ORCH_PORT', '5001')
u=f'http://127.0.0.1:{port}/preview?target=http%3A%2F%2F127.0.0.1%3A{port}%2Fstatic%2Ftest_preview_ext.html'
t=requests.get(u)
print('status:', t.status_code)
print(t.text[:800])
print('\n--- base tag present?', 'base href' in t.text)
print('contains /static before?', '/static/' in t.text)
print('contains http absolute?', f'http://127.0.0.1:{port}/static/' in t.text)
