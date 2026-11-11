# Log pipeline

[← Technical documentation](README.md)

## How an event travels end to end

The complete journey of a single Nginx access log line:

```
1. Nginx writes:
   192.168.1.5 - - [04/May/2026:15:30:00 +0100] "GET /api/v1 HTTP/1.1" 200 1234 "-" "curl/7.88"

2. Filebeat (on the Nginx host) reads /var/log/nginx/access.log
   → adds bench.t_filebeat_ns (nanosecond timestamp)
   → compresses with gzip
   → sends JSON to kafka:9094, topic "logs-nginx-default"

3. Kafka buffers the message in topic logs-nginx-default
   → durable, survives Logstash restarts

4. Logstash pipeline "nginx" consumes from kafka:9092
   → grok: parses IP, method, URL, status code, bytes, referrer, user agent
   → date: parses the nginx timestamp → @timestamp
   → useragent: enriches user_agent fields
   → mutate: renames fields to ECS (source.ip, http.request.method…)
   → ruby: records bench.t_logstash_ns and computes latency deltas
   → outputs to Elasticsearch index "bench-nginx-access"

5. Kibana
   → Data View "Nginx Logs"
   → Detection rules query the index for suspicious patterns
```

## Kafka topics and Elasticsearch indices

| Source | Kafka topic | Elasticsearch index |
| --- | --- | --- |
| Nginx access/error logs | `logs-nginx-default` | `bench-nginx-access` |
| Linux `/var/log/auth.log` | `logs-linux-auth-default` | `logs-linux.auth-default` |
| Linux `/var/log/audit/audit.log` | `logs-linux-audit-default` | `logs-linux.audit-default` |
| Windows Event Log (Security) | `logs-windows-security-default` | `logs-windows.security-default` |
| pfSense filterlog (syslog) | `logs-firewall-pfsense-default` | `logs-pfsense.firewall-default` |

Parse failures in the auditd pipeline go to `logs-linux.audit-parse-errors`, so they can be inspected without data loss.

## Logstash pipelines

Logstash runs in multi-pipeline mode. The manifest [`stack/pipeline.yaml`](../stack/pipeline.yaml) defines each pipeline with its own worker count and batch settings. Pipelines are isolated: a failure or backlog in one does not affect the others. The [evaluation](../evaluation/README.md#rq3-attack-visibility-during-log-flooding) shows that this isolation, rather than separate topics alone, keeps attack events visible while another source floods the SIEM.

| Pipeline | Config | Workers | Batch size |
| --- | --- | ---: | ---: |
| `nginx` | `nginx.conf` | 2 | 125 |
| `firewall` | `firewall-pfsense.conf` | 1 | 50 |
| `windows` | `windows-security.conf` | 2 | 125 |
| `linux-auth` | `linux-auth.conf` | 1 | 50 |
| `linux-auditd` | `linux-auditd.conf` | 1 | 50 |

### `nginx.conf`: web access and error logs

- Parses the standard nginx combined log format with grok.
- Classifies HTTP status codes into `log.level`: `error` (5xx), `warn` (4xx), `info` (2xx/3xx).
- Enriches user agent strings with the `useragent` filter.
- Renames fields to ECS: `source.ip`, `url.original`, `http.request.method`, `http.response.status_code`.

### `linux-auth.conf`: SSH and sudo events

- Three grok patterns: SSH accepted login, SSH failed login, sudo command.
- Sets `event.outcome` to `success` or `failure` from the message content.
- Sets `event.category` to `authentication` or `admin`.

### `linux-auditd.conf`: kernel audit subsystem

- Handles two input formats: structured Auditbeat ECS events and raw `type=SYSCALL msg=audit(...)` lines.
- Parses raw lines with grok, then extracts key=value pairs with the `kv` filter.
- Maps auditd event types (`EXECVE`, `USER_LOGIN`, `PATH`…) to ECS categories.
- Routes failed parses to a separate error index.

### `windows-security.conf`: Windows Event Log

Winlogbeat already sends structured JSON, so this pipeline only enriches. It maps known Event IDs to ECS fields:

| Event ID | Action | Category / outcome |
| --- | --- | --- |
| `4624` | logon-success | authentication / success |
| `4625` | logon-failed | authentication / failure |
| `4740` | account-locked | iam / failure |
| `4672` | privilege-assigned | iam / admin |

### `firewall-pfsense.conf`: pfSense packet filter logs

- Parses the syslog filterlog format: rule number, interface, action, direction, IP version.
- Sets `event.category: network` and `observer.type: firewall`.
- Classifies `block` actions as `log.level: warn`.

## Adding a new log source

1. Copy [`collectors/filebeat/template/filebeat.yml`](../collectors/filebeat/template/filebeat.yml) and point it at the new log file and a new Kafka topic (`logs-<source>-default`).
2. Copy [`stack/pipelines/template/pipeline.conf`](../stack/pipelines/template/pipeline.conf) to `stack/pipelines/<source>.conf`, set the topic, the parsing filters and the output index.
3. Register the pipeline in [`stack/pipeline.yaml`](../stack/pipeline.yaml) with its own `pipeline.id`, workers and batch size.
4. Add a Data View for the new index in [`utils/data-views.json`](../utils/data-views.json).
5. Restart Logstash (`docker compose restart logstash` in `stack/`) and check the event counts with `make verify`.
