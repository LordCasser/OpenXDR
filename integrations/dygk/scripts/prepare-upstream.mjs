import { readFile, writeFile, mkdir, cp } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve, join, dirname } from 'node:path';
import { knownSourceKinds } from '../web/state.mjs';
import { upstreamGit } from './upstream-git.mjs';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const lock = JSON.parse(await readFile(join(root, 'upstream.lock.json'), 'utf8'));
export async function prepare(source, allowFetch = true, refresh = false) {
  const target = join(root, '.upstream', lock.commit);
  const overlayHash = createHash('sha256').update(await readFile(join(root, 'web/export-feed.mjs'))).update(await readFile(fileURLToPath(import.meta.url))).digest('hex');
  try {
    if (refresh) { const error = new Error('显式重建缓存'); error.code = 'ENOENT'; throw error; }
    const stamp = JSON.parse(await readFile(join(target, '.prepared.json'), 'utf8'));
    if (stamp.patch !== overlayHash) throw new Error('导出适配变更，需要使用 prepare-upstream --refresh 重新准备上游目录');
    for (const [file, expected] of Object.entries(stamp.files)) {
      if (createHash('sha256').update(await readFile(join(target, file))).digest('hex') !== expected) throw new Error('本地上游缓存已变化：' + file);
    }
    return target;
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!allowFetch) throw new Error('运行依赖缺失，必须在构建阶段准备上游；运行时不下载代码');
  if (!source) {
    source = join(root, '.downloads', lock.commit);
    await mkdir(source, { recursive: true });
    const git = args => upstreamGit(source, args, lock.repository);
    git(['init']); git(['fetch', '--depth', '1', lock.repository, lock.commit]); git(['checkout', '--detach', 'FETCH_HEAD']);
  }
  source = resolve(source);
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: source, encoding: 'utf8' }).trim();
  if (commit !== lock.commit) throw new Error('上游 commit 不匹配');
  await mkdir(target, { recursive: true });
  for (const [file, expected] of Object.entries(lock.files)) {
    const content = await readFile(join(source, file));
    // Git 的 Windows checkout 可能把 LF 转成 CRLF；锁定规范化后的文本。
    const normalized = content.toString('utf8').replaceAll('\r\n', '\n');
    if (createHash('sha256').update(normalized).digest('hex') !== expected) throw new Error('上游文件摘要不匹配：' + file);
    await mkdir(dirname(join(target, file)), { recursive: true });
    await writeFile(join(target, file), normalized);
  }
  await cp(join(source, 'tests'), join(target, 'tests'), { recursive: true });
  for (const file of Object.keys(lock.files).filter(name => name.startsWith('lib/') && name.endsWith('.js'))) {
    const content = await readFile(join(target, file), 'utf8');
    for (const match of content.matchAll(/event\('([^']+)'/g)) if (!knownSourceKinds.has(match[1])) throw new Error('候选上游新增事实，需先适配：' + match[1]);
  }
  const serverFile = join(target, 'lib/server.js');
  let server = await readFile(serverFile, 'utf8');
  const replace = (before, after) => {
    if (server.split(before).length !== 2) throw new Error('上游事件适配位置不匹配，停止更新');
    server = server.replace(before, after);
  };
  replace("import { DatabaseSync } from 'node:sqlite';", "import { DatabaseSync } from 'node:sqlite';\nimport { createEventFeed } from './openxdr-export.js';");
  replace("  const deleteEvents = db.prepare", "  const exportFeed = createEventFeed(db, {maxEvents,retention,now,quarantineTTL:sessionTTL});\n  const deleteEvents = db.prepare");
  replace("    const item = {ts:now(), kind, ip, session, data};", "    let item; exportFeed.transaction(() => { item = {ts:now(), kind, ip, session, data};");
  replace("    try { options.onEvent?.(item); }", "    item = exportFeed.append(item);\n    });\n    try { options.onEvent?.(item); }");
  const profileUpdate = "db.prepare('UPDATE sessions SET stage=1,csrf=? WHERE id=? AND stage=0 AND csrf=?').run(csrf,s.id,s.csrf)";
  const profileEvents = "        event('profile_submitted',ip,s.id,{framework:body.framework,version:body.version,provenance:'self_reported_unverified',credential:'synthetic_compat_key'});\n        event('honeypot_triggered',ip,s.id,{stage:'profile',credential:'synthetic_compat_key'});";
  replace(profileEvents, '');
  replace('const changed=' + profileUpdate + ';', 'const changed=exportFeed.transaction(() => { const changed=' + profileUpdate + '; if(changed.changes) {\n' + profileEvents + '\n} return changed; });');
  const confirmUpdate = "db.prepare('UPDATE sessions SET stage=2,csrf=? WHERE id=? AND stage=1 AND csrf=?').run(token(),s.id,s.csrf)";
  const confirmEvent = "        event('honeypot_completed',ip,s.id,{model:body.model,provenance:'self_reported_unverified'});";
  replace(confirmEvent, '');
  replace('const changed=' + confirmUpdate + ';', 'const changed=exportFeed.transaction(() => { const changed=' + confirmUpdate + '; if(changed.changes) {\n' + confirmEvent + '\n} return changed; });');
  const banWrite = "    db.prepare('INSERT INTO bans VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET until=excluded.until').run(ip,until);\n    event('ip_banned',ip,session,{until,triggerStage});";
  replace(banWrite, '    exportFeed.transaction(() => {\n' + banWrite + '\n    });');
  replace("    clear: () => { quarantine?.entries.clear(); db.exec('DELETE FROM client_challenges; DELETE FROM sessions; DELETE FROM bans; DELETE FROM events;'); },", "    readEvents: (cursor,limit) => exportFeed.read(cursor,limit),\n    clear: () => { db.exec('BEGIN IMMEDIATE'); try { quarantine?.entries.clear(); db.exec('DELETE FROM client_challenges; DELETE FROM sessions; DELETE FROM bans; DELETE FROM events;'); exportFeed.clear(); db.exec('COMMIT'); } catch(error) {db.exec('ROLLBACK');throw error;} },");
  replace('  function isBlocked(ip) {', '  if (quarantine) quarantine.restore(exportFeed.quarantineState());\n  function isBlocked(ip) {');
  await writeFile(serverFile, server);
  const quarantineFile = join(target, 'lib/quarantine.js');
  const quarantine = await readFile(quarantineFile, 'utf8');
  const before = '  return { active, activate, handle, entries };';
  if (quarantine.split(before).length !== 2) throw new Error('上游隔离状态适配位置不匹配');
  await writeFile(quarantineFile, quarantine.replace(before, `  const restore = rows => { for (const row of rows) { if (row.until > now()) entries.set(row.ip, {until:row.until,requests:row.requests,revealed:new Set(row.revealed),probes:0,label:digest(row.ip).slice(0,12)}); } };
  return { active, activate, handle, entries, restore };`));
  await cp(join(root, 'web/export-feed.mjs'), join(target, 'lib/openxdr-export.js'));
  const files = {};
  for (const file of [...Object.keys(lock.files).filter(name => name === 'package.json' || name.startsWith('lib/')), 'lib/openxdr-export.js']) files[file] = createHash('sha256').update(await readFile(join(target, file))).digest('hex');
  await writeFile(join(target, '.prepared.json'), JSON.stringify({ patch: overlayHash, files }, null, 2));
  return target;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const sourceIndex = process.argv.indexOf('--source');
  console.log(await prepare(sourceIndex < 0 ? undefined : process.argv[sourceIndex + 1], true, process.argv.includes('--refresh')));
}
