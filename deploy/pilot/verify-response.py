#!/usr/bin/env python3
"""对已有 Windows 处置指令发起只读状态探测；不重放处置、不自动结案。"""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import time
import urllib.parse
import urllib.request


def ps_literal(value):
    return "'" + value.replace("'", "''") + "'"


def script_for(command, probe=None):
    kind, target = command['kind'], command.get('target') or ''
    if kind in ('quarantine_file', 'restore_file'):
        if not target:
            raise ValueError('原指令缺少文件目标')
        return ("$p=" + ps_literal(target) + ";$e=Test-Path -LiteralPath $p;"
                "[pscustomobject]@{exists=$e;sha256=$(if($e){"
                "(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash}else{$null})}"
                "|ConvertTo-Json -Compress"), {'exists': kind == 'restore_file'}
    if kind in ('disable_account', 'enable_account'):
        if not target:
            raise ValueError('原指令缺少账号目标')
        return ("Get-LocalUser -Name " + ps_literal(target) +
                "|Select-Object Name,Enabled|ConvertTo-Json -Compress"), {
                    'Enabled': kind == 'enable_account'}
    if kind in ('isolate_host', 'unisolate_host', 'block_network', 'unblock_network'):
        if not probe:
            raise ValueError('网络复核必须指定 --probe IP:端口，并确认该端点在处置前可达')
        parsed = urllib.parse.urlsplit('tcp://' + probe)
        address, port = ipaddress.ip_address(parsed.hostname), parsed.port
        if not port or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError('探测地址必须为数字 IP:端口；IPv6 使用 [地址]:端口')
        if kind in ('block_network', 'unblock_network'):
            try:
                network = ipaddress.ip_network(target, strict=False)
            except ValueError as exc:
                raise ValueError('域名封锁需人工核对当时解析地址，工具不猜测目标') from exc
            if address not in network:
                raise ValueError('探测地址不在原封锁目标内')
        script = ("$c=New-Object Net.Sockets.TcpClient;$ok=$false;try{"
                  "$r=$c.BeginConnect(" + ps_literal(str(address)) + "," + str(port) +
                  ",$null,$null);if($r.AsyncWaitHandle.WaitOne(3000)){"
                  "$c.EndConnect($r);$ok=$true}}catch{}finally{$c.Dispose()};"
                  "[pscustomobject]@{reachable=$ok}|ConvertTo-Json -Compress")
        return script, {'reachable': kind in ('unisolate_host', 'unblock_network')}
    raise ValueError('此工具仅复核文件、账号和网络动作；不根据 PID 猜测进程身份')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--cookie-file', required=True, type=Path,
                        help='包含会话 Cookie 字符串的 JSON 文件，不写入报告')
    parser.add_argument('--command', required=True)
    parser.add_argument('--probe', help='处置前已确认可达的数字 IP:端口')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.output.exists():
        raise SystemExit('输出文件已存在，避免覆盖验收证据')
    cookie = json.loads(args.cookie_file.read_text())
    base = args.base_url.rstrip('/')
    if urllib.parse.urlsplit(base).scheme not in ('https', 'http'):
        raise SystemExit('平台地址必须为 HTTP(S) URL')

    def api(method, path, body=None):
        request = urllib.request.Request(base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type': 'application/json', 'Origin': base, 'Cookie': cookie})
        with urllib.request.urlopen(request, timeout=35) as response:
            return json.load(response)

    command = api('GET', '/api/commands/' + args.command)
    if command['status'] != 'succeeded':
        raise SystemExit('原指令不是成功终态，先核对回执；不会自动重试处置')
    assets = api('GET', '/api/assets')
    asset = next((a for a in assets if a['id'] == command['assetId']), {})
    if (asset.get('os') or '').lower() != 'windows':
        raise SystemExit('当前探测模板仅支持 Windows')
    script, expected = script_for(command, args.probe)
    script = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" + script
    encoded = base64.b64encode(script.encode('utf-16le')).decode()
    report = {'source_command': command['id'], 'asset': command['assetId'],
              'kind': command['kind'], 'target': command.get('target'),
              'probe': args.probe, 'expected': expected,
              'status': 'dispatching', 'probe_started_at': time.time(),
              'meaning': '仅记录当前状态；探测失败不等于处置有效，状态匹配不等于威胁清除'}
    def save():
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    save()
    # POST 失败或超时不会重试；报告保留 dispatching，操作者须先查询平台指令记录。
    result = api('POST', '/api/commands', {
        'kind': 'exec', 'assetId': command['assetId'], 'timeoutMs': 15000,
        'cmd': 'powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + encoded,
    })
    report.update(status='waiting', probe_command=result['id'])
    save()
    deadline = time.monotonic() + 45
    while result['status'] in ('pending', 'sent', 'running') and time.monotonic() < deadline:
        time.sleep(1)
        result = api('GET', '/api/commands/' + result['id'])
    report['receipt'] = {k: result.get(k) for k in (
        'id', 'status', 'exitCode', 'stdout', 'stderr', 'completedAt', 'detail')}
    report['status'] = 'inconclusive'
    if result['status'] == 'succeeded' and result.get('exitCode') == 0:
        try:
            observed = json.loads(result.get('stdout') or '')
            if not isinstance(observed, dict):
                raise ValueError('探测结果不是对象')
            report.update(status='observed', observed=observed,
                          state_matches=all(observed.get(k) == v for k, v in expected.items()))
        except ValueError:
            report['parse_error'] = True
    save()
    print(json.dumps({k: report.get(k) for k in ('status', 'state_matches', 'probe_command')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
