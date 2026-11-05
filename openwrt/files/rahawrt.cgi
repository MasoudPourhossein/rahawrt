#!/usr/bin/python3
"""uhttpd CGI bridge. Never trust forwarding headers from the browser."""
import http.client
import os
import sys

try:
    length = int(os.environ.get('CONTENT_LENGTH', '0') or '0')
    if not 0 <= length <= 65536:
        raise ValueError('request too large')
    path = os.environ.get('PATH_INFO', '')
    if not path.startswith('/wrt/api/v1/') or '\r' in path or '\n' in path:
        raise ValueError('invalid API path')
    query=os.environ.get('QUERY_STRING','')
    if len(query)>2048 or '\r' in query or '\n' in query:
        raise ValueError('invalid query')
    if query:
        path+='?'+query
    method=os.environ.get('REQUEST_METHOD','GET')
    marker=os.environ.get('HTTP_X_RAHAWRT_REQUEST','')
    # uhttpd forwards a fixed CGI header allowlist. A same-method override is
    # only a CORS-unsafe request marker; it never changes the HTTP method.
    if os.environ.get('HTTP_X_HTTP_METHOD_OVERRIDE')==method:marker='1'
    headers = {'Content-Type': os.environ.get('CONTENT_TYPE', ''),
               'X-RahaWRT-Client': os.environ.get('REMOTE_ADDR', ''),
               'X-RahaWRT-HTTPS': os.environ.get('HTTPS', ''),
               'Cookie': os.environ.get('HTTP_COOKIE', ''),
               'Authorization': os.environ.get('HTTP_AUTHORIZATION', ''),
               'X-RahaWRT-Request': marker}
    conn = http.client.HTTPConnection('127.0.0.1', 9080, timeout=35)
    conn.request(method, path, sys.stdin.buffer.read(length), headers)
    response = conn.getresponse()
    output = f'Status: {response.status} {http.client.responses.get(response.status, "Response")}\r\n'
    for key, value in response.getheaders():
        if key.lower() not in ('server', 'date', 'connection', 'transfer-encoding'):
            output += f'{key}: {value}\r\n'
    sys.stdout.buffer.write((output+'\r\n').encode()+response.read())
    conn.close()
except Exception:
    sys.stdout.buffer.write(b'Status: 503 Service Unavailable\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n{"error":"RahaWRT service unavailable or invalid request"}')
