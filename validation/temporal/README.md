# 时序检测回放

`cases.json` 是人工构造的归一化事件语料，使用仓库基础规则和 `temporal-rules/` 实验规则。
命令行仅作为事件文本参与匹配，测试不会执行命令、下载文件或修改主机。
`example.invalid` 与 `192.0.2.10` 是占位地址；不把本语料冒充真实攻击采集或 Atomic 测试实录。

从 `server/` 运行：

```sh
go test ./internal/temporal -run TestRepositoryTemporalCorpus -count=1 -v
# 使用独立测试 PostgreSQL，并配置 INTEGRATION_DATABASE_URL：
go test -tags integration -p 1 ./internal/ingest -run TestRepositoryTemporalRulesPersistLateReplay -count=1 -v
```

两个测试分别由现有 CI 的单测、集成测试步骤自动包含，不需要新增后台服务。

20 个确定性回放用例覆盖计数阈值/窗口边界、乱序、重投、成功认证负例，以及下载执行后敏感文件变更的
先后关系、同时间/反转/窗口外、跨组/跨主机、普通下载/普通文件负例和 OS 适用范围。
每个事件先经过基础规则原文匹配，再转换为候选；语料不直接填入规则命中。
回放逐步按到达顺序求值，使用独立的事件时间，并在中途从规则归档重建快照。
核对规则 ID、终点 ID、完整有序证据，不只检查“是否有告警”。

数据库专项针对两条实际规则，验证终点先到、处理器重建、前序补到及全部重投后，
持久命中只有一条、告警计数为 1，证据顺序正确。这覆盖处理器恢复，不模拟 OS 进程崩溃或电源故障。
原有数据库测试继续覆盖组切换、事务回滚、证据保留和并发；本语料不替代实机采集、容量测试或生产调优。
