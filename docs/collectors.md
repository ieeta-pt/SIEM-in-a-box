# Collectors

[← Technical documentation](README.md)

Collector configurations live in [`collectors/`](../collectors/). Copy the relevant config to the monitored host, replace `<IP_DO_SIEM>` with the IP of the Docker host running the SIEM, and start the collector. All collectors publish to the external Kafka listener on port `9094`.

| Source | Collector | Config | Kafka topic |
| --- | --- | --- | --- |
| Linux auth | Filebeat | [`filebeat/linux-auth/filebeat.yaml`](../collectors/filebeat/linux-auth/filebeat.yaml) | `logs-linux-auth-default` |
| Linux auditd | Filebeat | [`filebeat/linux-auditd/filebeat.yaml`](../collectors/filebeat/linux-auditd/filebeat.yaml) | `logs-linux-audit-default` |
| Linux combined | Filebeat | [`filebeat/linux-full/filebeat.yml`](../collectors/filebeat/linux-full/filebeat.yml) | one per input |
| Nginx | Filebeat | [`filebeat/nginx/filebeat.yaml`](../collectors/filebeat/nginx/filebeat.yaml) | `logs-nginx-default` |
| Windows Security | Winlogbeat | [`winlogbeat/windows-security/winlogbeat.yaml`](../collectors/winlogbeat/windows-security/winlogbeat.yaml) | `logs-windows-security-default` |
| pfSense firewall | rsyslog (omkafka) | [`syslog/pfsense/rsyslog.conf`](../collectors/syslog/pfsense/rsyslog.conf) | `logs-firewall-pfsense-default` |

## Filebeat: Linux auth

Monitors `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS) and captures SSH logins (accepted and failed) and sudo usage.

```bash
# On the monitored Linux host, after installing Filebeat:
cp collectors/filebeat/linux-auth/filebeat.yaml /etc/filebeat/filebeat.yml
sed -i 's/<IP_DO_SIEM>/192.168.0.23/' /etc/filebeat/filebeat.yml
systemctl enable --now filebeat
```

## Filebeat: Linux auditd

Monitors `/var/log/audit/audit.log` and requires the `auditd` daemon on the host:

```bash
apt install auditd
systemctl enable --now auditd
```

Sends raw auditd lines; Logstash does the full parsing. Uses a larger `harvester_buffer_size` (64 KB) because auditd writes in high-volume bursts.

## Filebeat: Linux combined

Combines auth, auditd and syslog in a single Filebeat instance. Each input sets a `kafka_topic` field and the output routes on it with `topic: '%{[kafka_topic]}'`.

| Input | Path | Topic |
| --- | --- | --- |
| linux-auth | `/var/log/auth.log` | `logs-linux-auth-default` |
| linux-auditd | `/var/log/audit/audit.log` | `logs-linux-audit-default` |
| linux-syslog | `/var/log/syslog` | `logs-linux-syslog-default` (disabled: no pipeline yet) |

[`collectors/filebeat/linux-full/docker-compose.yml`](../collectors/filebeat/linux-full/docker-compose.yml) runs this Filebeat as a container on the monitored host.

## Filebeat: Nginx

Two inputs, `access.log` (`log_type: access`) and `error.log` (`log_type: error`), both sent to `logs-nginx-default`. Includes the latency processor that stamps `bench.t_filebeat_ns` (nanoseconds since epoch) on each event, used to measure pipeline latency.

## Winlogbeat: Windows Security

Runs as a Windows service and reads two channels:

- **Security**: Event IDs 4624, 4625, 4740, 4672, 4648, 4776, 4768, 4769 (logons, lockouts, Kerberos, NTLM).
- **System**: levels critical, error and warning (last 24 h).

Winlogbeat serialises events as structured JSON, so Logstash only enriches them.

```powershell
# On the Windows host:
# 1. Download Winlogbeat from elastic.co
# 2. Copy winlogbeat.yaml to the installation directory as winlogbeat.yml
# 3. Replace <IP_DO_SIEM>
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

## rsyslog: pfSense firewall

pfSense sends packet filter logs by syslog (UDP/TCP 514) to a Linux intermediary running rsyslog. The omkafka module forwards only `filterlog` messages (`$programname == "filterlog"`) to Kafka.

```bash
apt install rsyslog-kafka   # Debian/Ubuntu
dnf install rsyslog-kafka   # RHEL/Fedora
```

Then configure pfSense to send remote syslog to the rsyslog host on port 514.

> UDP senders cannot retry. Kafka buffers their events while Elasticsearch or Logstash is unavailable, but the broker itself is a single point of failure for them; see [RQ4 in the evaluation](../evaluation/README.md#rq4-resource-cost-and-broker-failure).
