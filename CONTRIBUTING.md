# 参与贡献

欢迎 Issue 与 PR。动手前建议先开 Issue 说明要解决的问题，避免方向不一致白费功夫。

## 开发环境

- server：Go 1.25，PostgreSQL（`docker compose up -d postgres`）
- agent / sensor：Rust stable；内核特性（`ebpf` / `xdp`）需 nightly 与 bpf-linker
- web：Node.js，`npm ci`

架构与代码组织见 [docs/README.md](docs/README.md) 与 [AGENTS.md](AGENTS.md)。

## 提交前检查

CI 与以下命令一致，本地先跑通：

```bash
# server/
gofmt -l .            # 必须无输出
go vet ./... && go test ./...
go run ./cmd/sigmacheck --strict ../rules
go run ./cmd/detectcheck --strict

# agent/ 与 sensor/
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test

# web/
npm run lint && npm run build
```

集成测试需要 Postgres：

```bash
INTEGRATION_DATABASE_URL=postgres://openxdr:openxdr@localhost:5432/openxdr_test?sslmode=disable \
  go test -tags integration -p 1 ./...
```

## 约定

- 代码注释、日志与文档使用简体中文；控制台可见文案中英文同时维护。
- 拿不准就拒绝或降级，绝不静默产出错误数据。
- 改 `rules/` 后必须跑 `sigmacheck` 与 `detectcheck`，检测能力变化时同步更新 `validation/` 语料。
- 改响应处置（`server/internal/response`、`grpcsvc/commands.go`、agent `respond/`）或命令审批
  （`commandgate`）时，不得削弱任何一道闸门。
- 改 Windows 相关采集代码时，用 `x86_64-pc-windows-gnu` 交叉编译跑 clippy。
- 一个 PR 只做一件事；行为变化同步更新 `docs/`。

## 许可

提交的贡献按 [Apache License 2.0](LICENSE) 授权。
