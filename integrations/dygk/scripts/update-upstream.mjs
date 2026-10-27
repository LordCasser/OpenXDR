import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { root, lock } from './prepare-upstream.mjs';
import { upstreamGit } from './upstream-git.mjs';
const commit = process.argv[2];
if (!/^[a-f0-9]{40}$/.test(commit || '')) throw new Error('必须提供完整的上游 commit');
const source = join(root, '.downloads', commit);
await mkdir(source, { recursive: true });
const git = args => upstreamGit(source, args, lock.repository);
git(['init']); git(['fetch', '--depth', '1', lock.repository, commit]); git(['checkout', '--detach', 'FETCH_HEAD']);
const paths = git(['ls-tree', '-r', '--name-only', 'HEAD']).trim().split('\n').filter(name => name === 'package.json' || name.startsWith('lib/') || name.startsWith('tests/') || name.startsWith('examples/') || name === 'experiments/trace_analysis.py');
const files = {};
for (const name of paths) files[name] = createHash('sha256').update((await readFile(join(source, name), 'utf8')).replaceAll('\r\n', '\n')).digest('hex');
const pkg = JSON.parse(await readFile(join(source, 'package.json'), 'utf8'));
const before = await readFile(join(root, 'upstream.lock.json'));
try {
  await writeFile(join(root, 'upstream.lock.json'), JSON.stringify({ ...lock, commit, version: pkg.version, license: pkg.license, files }, null, 2) + '\n');
  execFileSync(process.execPath, ['scripts/prepare-upstream.mjs', '--source', source, '--refresh'], { cwd: root, stdio: 'inherit' });
  execFileSync(process.execPath, ['scripts/test-upstream.mjs'], { cwd: root, stdio: 'inherit' });
  execFileSync(process.execPath, ['--test', '--test-force-exit', 'tests/feed.test.mjs'], { cwd: root, stdio: 'inherit' });
  console.log('候选锁文件已更新。继续运行平台端到端及兼容检查，再提交变更。');
} catch (error) { await writeFile(join(root, 'upstream.lock.json'), before); throw error; }
