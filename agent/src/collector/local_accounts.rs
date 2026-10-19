//! Linux 本地账号清单，仅读取 passwd 的非凭据字段，不进行 NSS/目录网络查询。
use std::collections::BTreeSet;
use std::io::{self, Read};

use serde::Serialize;

const MAX_BYTES: usize = 1024 * 1024;
const MAX_ACCOUNTS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Account {
    name: String,
    uid: u32,
    gid: u32,
    shell: String,
}

pub(super) fn snapshot() -> io::Result<Vec<Account>> {
    read_accounts(std::fs::File::open("/etc/passwd")?)
}

fn read_accounts(reader: impl Read) -> io::Result<Vec<Account>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    parse(std::str::from_utf8(&bytes).map_err(|_| invalid())?)
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "本地账号清单格式无效或超过上限")
}

fn parse(text: &str) -> io::Result<Vec<Account>> {
    let mut accounts = Vec::new();
    let mut names = BTreeSet::new();
    for line in text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7
            || fields[0].is_empty()
            || fields[0].len() > 256
            || fields[6].len() > 512
        {
            return Err(invalid());
        }
        if fields[0].chars().any(char::is_control)
            || fields[6].chars().any(char::is_control)
            || !names.insert(fields[0])
        {
            return Err(invalid());
        }
        // 不取 password、GECOS 和 home 字段；账号共享 UID 合法，不能按 UID 去重。
        let uid = fields[2].parse::<u32>().map_err(|_| invalid())?;
        let gid = fields[3].parse::<u32>().map_err(|_| invalid())?;
        accounts.push(Account {
            name: fields[0].into(),
            uid,
            gid,
            shell: fields[6].into(),
        });
        if accounts.len() > MAX_ACCOUNTS {
            return Err(invalid());
        }
    }
    accounts.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(accounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_local_ids_without_credentials() {
        let rows = parse(
            "root:private-hash:0:0:private-gecos:/root:/bin/bash\nalias:x:0:0::/:/bin/false\n",
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "alias");
        assert_eq!(rows[0].uid, rows[1].uid);
        let json = serde_json::to_string(&rows).unwrap();
        assert!(!json.contains("private"));
        assert!(!json.contains("/root"));
        assert!(!json.contains("enabled"));
    }

    #[test]
    fn rejects_invalid_or_partial_inventory() {
        for value in [
            "bad",
            "u:x:no:1::/:/bin/sh",
            "u:x:4294967296:1::/:/bin/sh",
            "u:x:1:1::/:/bin/sh\nu:x:2:2::/:/bin/sh",
            ":x:0:0::/:/bin/sh",
        ] {
            assert!(parse(value).is_err());
        }
        let text = (0..=MAX_ACCOUNTS)
            .map(|n| format!("u{n}:x:{n}:1::/:/bin/sh\n"))
            .collect::<String>();
        assert!(parse(&text).is_err());
        assert!(read_accounts(&vec![b'a'; MAX_BYTES + 1][..]).is_err());
        assert!(read_accounts(&[0xff][..]).is_err());
        assert_eq!(parse("").unwrap(), Vec::<Account>::new());
    }
}
