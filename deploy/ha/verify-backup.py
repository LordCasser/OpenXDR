#!/usr/bin/env python3
"""在无网络的临时 PostgreSQL 容器完整恢复备份，结束后删除容器和临时数据卷。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', required=True, type=Path)
    parser.add_argument('--image', default='postgres:16')
    args = parser.parse_args()
    os.umask(0o077)
    backup = args.backup.resolve()
    manifest = json.loads((backup / 'manifest.json').read_text())
    if manifest['status'] != 'complete':
        raise SystemExit('备份尚未完成')
    if shutil.disk_usage(backup).free < manifest['database_bytes'] * 1.2:
        raise SystemExit('恢复前至少预留数据库总大小的 1.2 倍空间')
    if set(manifest['files']) != {'roles.sql', 'runtime.tar.gz', 'database.dump'}:
        raise SystemExit('备份清单缺少必要文件')
    if (backup / 'restore.log').exists():
        raise SystemExit('恢复日志已存在；保留旧报告后再进行下一次验收')
    for name, expected in manifest['files'].items():
        digest = hashlib.sha256()
        with (backup / name).open('rb') as src:
            for block in iter(lambda: src.read(8 * 1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != expected['sha256']:
            raise SystemExit(f'{name} 校验和不匹配')
    name = 'openxdr-restore-' + uuid.uuid4().hex[:12]
    volume = name + '-data'
    report = {'status': 'running', 'network': 'none', 'image': args.image,
              'container': name, 'volume': volume,
              'started_at': time.time(), 'checksums_valid': True}
    report_path = backup / 'restore-verification.json'
    report_path.write_text(json.dumps(report, indent=2))
    subprocess.run(['docker', 'volume', 'create', volume], check=True, stdout=subprocess.DEVNULL)
    try:
        subprocess.run([
            'docker', 'run', '-d', '--name', name, '--network', 'none',
            '-e', 'POSTGRES_USER=postgres',
            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '--mount', f'type=volume,src={volume},dst=/var/lib/postgresql/data',
            '--mount', f'type=bind,src={backup},dst=/backup,readonly', args.image,
        ], check=True, stdout=subprocess.DEVNULL)
        base = ['docker', 'exec', name]
        psql = ['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres']
        for _ in range(60):
            result = subprocess.run(base + ['pg_isready', '-h', '127.0.0.1', '-U', 'postgres'],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('临时数据库未就绪')
        with (backup / 'restore.log').open('xb') as log:
            def run(command):
                subprocess.run(command, stdout=log, stderr=log, check=True)
            # 默认超级用户已由 initdb 创建；保留其 ALTER 和原始授权者语义。
            roles = (backup / 'roles.sql').read_bytes()
            roles = b'\n'.join(line for line in roles.split(b'\n') if line != b'CREATE ROLE postgres;')
            subprocess.run(base[:2] + ['-i'] + base[2:] + psql + ['-d', 'postgres'],
                           input=roles, stdout=log, stderr=log, check=True)
            run(base + ['createdb', '-U', 'postgres', 'openxdr_restore'])
            print('开始完整恢复数据、索引和约束', flush=True)
            run(base + ['env', 'PGOPTIONS=-c maintenance_work_mem=256MB',
                        'pg_restore', '--exit-on-error', '--jobs=2',
                        '-U', 'postgres', '-d', 'openxdr_restore',
                        '/backup/database.dump'])
        sql = """SELECT json_build_object(
          'events', (SELECT count(*) FROM events),
          'assets', (SELECT count(*) FROM assets),
          'incidents', (SELECT count(*) FROM incidents),
          'commands', (SELECT count(*) FROM commands),
          'settings', (SELECT count(*) FROM settings),
          'invalid_indexes', (SELECT count(*) FROM pg_index WHERE NOT indisvalid),
          'event_range', (SELECT json_build_array(min(ts),max(ts)) FROM events));"""
        result = subprocess.check_output(base + psql + ['-At', '-d', 'openxdr_restore', '-c', sql], text=True)
        report['restored'] = json.loads(result)
        if report['restored']['invalid_indexes']:
            raise RuntimeError('恢复库存在无效索引')
        report['status'] = 'complete'
        print('完整恢复验证通过', flush=True)
    except Exception as exc:
        report.update(status='failed', error=type(exc).__name__)
        raise
    finally:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cleanup = subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL)
        report.update(finished_at=time.time(), temporary_volume_removed=cleanup.returncode == 0)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
