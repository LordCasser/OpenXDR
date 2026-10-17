# OpenXDR

[![CI](https://github.com/yaklang/OpenXDR/actions/workflows/ci.yml/badge.svg)](https://github.com/yaklang/OpenXDR/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[中文](README.md) | English

An open-source XDR platform: EDR + SIEM + network traffic analysis, with AI-driven noise reduction and operations.

**Onboarded means operated, onboarded means secured.** Install the agent on a host and put it in a group,
and it immediately gets continuous collection, detection, daily inspection and an AI assistant you can talk to.
People make the calls instead of digging through alert lists.

**Ten thousand alerts in, three real incidents out.**

> Detailed documentation under `docs/` is currently written in Chinese.

## What it does

- **One-command onboarding**: the console issues per-group enrollment tokens; one command installs the agent
  on Linux / Windows, generates the private key locally and gets a host-bound certificate from the server.
  Afterwards, drop a new build into the distribution directory and online agents upgrade themselves.
  Existing ops documents can be imported, with credentials encrypted at rest and SSH onboarding authorized per group.
- **Collection that adapts**: processes, files, persistence points, logon and security logs, outbound connections,
  kernel modules. eBPF / ETW are optional and fall back automatically to netlink, fanotify or polling —
  weaker collection is preferred over fake data. The network sensor emits session metadata only
  (DNS / TLS JA3 and certificates / HTTP), no PCAP. Syslog ingestion is built in.
- **Layered noise reduction**: Sigma-compatible rules (hot reload, ATT&CK matrix that flags
  "rule exists but no data source"), threat intel matching with built-in public feeds such as abuse.ch,
  persistent dedup, revocable suppressions, entity-based correlation into incident graphs, UEBA first-seen detection,
  and finally AI triage that investigates with tools. Low-severity benign incidents are auto-closed after a grace period;
  anything that needs human review stays with humans.
- **AI assistant and inspections**: run commands on the group's hosts, query the database through a per-group
  read-only view, track ops findings and file reports — all by conversation. Incidents and findings can be
  multi-selected and handed to the AI. Conversations run in the background on the server, so switching pages
  doesn't interrupt them. Preset tasks inspect every host in a group on a cron schedule and render HTML / PDF reports.
- **Humans stay in charge**: commands matching the high-risk list block until a group admin approves (with a notification);
  everything else runs directly. Process kill / host isolation are gated by a global switch and an isolation allowlist.
  Every login, approval and response action is audited.
- **Production-ready**: mTLS with host-bound certificates, three-tier RBAC plus group roles, NATS JetStream queues
  sharded by asset, multi-node servers, and a cross-host HA deployment with Patroni + Keepalived.

## Architecture

```
┌─────────┐  ┌──────────┐  ┌──────────┐
│  Agent  │  │  Sensor  │  │  Syslog  │
│endpoint │  │ network  │  │   logs   │
└────┬────┘  └────┬─────┘  └────┬─────┘
     └────────────┼─────────────┘  gRPC (mTLS), agent dials out
                  ▼
   ┌──────────────────────────────┐
   │ Server (Go)                  │
   │  normalize → JetStream queue │
   │  rules / intel / UEBA        │
   │  dedup → suppress → correlate│
   │  → AI triage                 │
   │  AI assistant · inspections  │──→ Webhook (DingTalk / Feishu / WeCom)
   │  · command approvals         │
   └──────────────┬───────────────┘
                  ▼
   PostgreSQL ←→ Web console (React)
```

## Quick start

```bash
docker compose up -d
# Console http://localhost:5173   API :8080   gRPC :8081
docker compose logs server | grep admin   # admin password generated on first start
```

Connect any OpenAI-compatible endpoint to enable AI triage and the AI assistant:

```bash
AI_BASE_URL=http://<inference>/v1 AI_MODEL=<model> PI_MODEL=<model> docker compose up -d
```

Then copy the install command from "Assets → Add host" and run it on the monitored host. Onboarding requires
an HTTPS console and mTLS; see the [deployment guide](docs/deployment.md) for the full steps,
collection modes, mTLS, intel, suppression, response actions and every configuration variable.

## Documentation

| Document | Content |
|---|---|
| [Deployment guide](docs/deployment.md) | Startup, onboarding, logs and intel, suppression and response, mTLS, configuration |
| [High availability](deploy/ha/README.md) | Patroni + 3-node JetStream + Keepalived VIP, rolling release |
| [AI assistant and inspections](docs/pi-backend.md) | Sessions, command list and approvals, read-only queries, findings, preset tasks |
| [Document import and onboarding](docs/host-enrollment.md) | Ops document import, credential encryption, SSH onboarding |
| [Architecture](docs/architecture.md) · [Collection](docs/collection.md) · [Event model](docs/events.md) · [Detection](docs/detection.md) | Design and implementation |
| [REST API](docs/api.md) · [Cluster](docs/cluster.md) · [Roadmap](docs/roadmap.md) | Integration, operations and plans |

## Status

v0.1.0 is the first public release. Linux collection, detection, the AI assistant and inspections run continuously
on a two-node HA deployment. Windows code is cross-compiled and linted in CI but still lacks systematic testing on
real machines. AI quality depends on the tool-calling ability of the model you connect: weaker models drift with
long context. The platform guarantees the AI cannot cross permission and approval boundaries, not that its
conclusions are right — incidents are still closed by people.

See the [roadmap](docs/roadmap.md) for known gaps and the [CHANGELOG](CHANGELOG.md) for changes.

## Contributing

Issues and PRs are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) first. Report security issues
privately as described in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
