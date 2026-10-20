"""仅用于本地靶场的显式 Banner 采集；不执行服务端文本。"""
import json
import socket
import paramiko

with socket.create_connection(('127.0.0.1', 2222), timeout=3) as sock:
    transport = paramiko.Transport(sock)
    transport.auth_timeout = 3
    try:
        transport.start_client(timeout=3)
        try:
            transport.auth_password('audit', 'probe')
        except paramiko.AuthenticationException:
            pass
        banner = transport.get_banner()
        if not banner:
            raise RuntimeError('SSH authentication banner absent')
        print(json.dumps({'source':'ssh_userauth_banner', 'target':'127.0.0.1:2222',
                          'trust':'untrusted_service_text',
                          'banner':banner.decode('utf-8', errors='replace')[:8192]}, ensure_ascii=False))
    finally:
        transport.close()
