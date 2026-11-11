# Configuration and operations

[← Technical documentation](README.md)

## Stack configuration (`stack/.env`)

All stack configuration comes from [`stack/.env`](../stack/.env). Edit it before the first `make up`.

| Variable | Default | Description |
| --- | --- | --- |
| `STACK_VERSION` | `8.19.7` | Version of all Elastic Stack images |
| `ELASTIC_PASSWORD` | `elastic` | Password of the `elastic` superuser |
| `KIBANA_PASSWORD` | `kibana` | Internal password of the `kibana_system` user |
| `ES_PORT` | `9200` | Elasticsearch host port |
| `KIBANA_PORT` | `5601` | Kibana host port |
| `FLEET_PORT` | `8220` | Fleet Server host port |
| `APMSERVER_PORT` | `8200` | APM Server host port |
| `CLUSTER_NAME` | `siem-cluster` | Elasticsearch cluster name |
| `LICENSE` | `basic` | License type (`basic` or `trial`) |
| `MEM_LIMIT` | `2147483648` | Memory limit per service (2 GB) |
| `ENCRYPTION_KEY` | *(set)* | Kibana encryption key for saved objects |
| `ELASTIC_APM_SECRET_TOKEN` | `supersecrettoken` | APM secret token |

## Production hardening

The defaults are for a lab. Before exposing the stack:

- Change `ELASTIC_PASSWORD`, `KIBANA_PASSWORD`, `ENCRYPTION_KEY` (at least 32 characters) and `ELASTIC_APM_SECRET_TOKEN`.
- The Kafka listeners use PLAINTEXT. Restrict port `9094` to the monitored hosts with a firewall, or configure TLS/SASL on Kafka and the collectors.
- Kafka runs as a single broker. If UDP sources matter, plan for broker monitoring and fast restart (see [RQ4](../evaluation/README.md#rq4-resource-cost-and-broker-failure)).

## Makefile

```
make up             Start the core stack and wait until Elasticsearch is healthy
make down           Stop containers (volumes are preserved)
make down-volumes   Stop containers and delete all volumes (data loss)
make status         Show container status and Elasticsearch cluster health
make verify         List Elasticsearch indices and Logstash pipeline event counts
make help           Print the available targets
```

Environment overrides, passed as `make up VAR=value`:

| Variable | Default |
| --- | --- |
| `ELASTIC_PASSWORD` | `elastic` |
| `ELASTIC_USER` | `elastic` |
| `ES_URL` | `https://localhost:9200` |
| `KIBANA_URL` | `https://localhost:5601` |
| `KAFKA_BOOTSTRAP` | `localhost:9094` |

## Detection rules

| Script | Purpose |
| --- | --- |
| [`scripts/provision-rules.sh`](../scripts/provision-rules.sh) | Waits for Kibana and provisions the detection rules found in `RULES_DIR` into the Detection Engine. |
| [`scripts/manage-rules.sh`](../scripts/manage-rules.sh) | CLI to manage rules: `list`, `stats`, `enable`, `disable`, `delete`, `export`, `test`, `create`. |

Both read `KIBANA_HOST` (default `https://localhost:5601`), `ELASTICSEARCH_USERNAME` (default `elastic`), `ELASTIC_PASSWORD` (required) and `VERIFY_SSL` (default `false`).

```bash
export ELASTIC_PASSWORD=elastic
./scripts/manage-rules.sh list --enabled-only
```

## Utilities

| Script | Purpose |
| --- | --- |
| [`utils/setup.sh`](../utils/setup.sh) | TLS certificate generation, run inside the `siem-setup` container. |
| [`utils/configure-fleet-ssl.sh`](../utils/configure-fleet-ssl.sh) | Fleet output SSL and service token setup. |
| [`utils/kibana-setup.sh`](../utils/kibana-setup.sh) | Creates Kibana Data Views through the API from [`data-views.json`](../utils/data-views.json). |
| [`utils/get-certs-details.sh`](../utils/get-certs-details.sh) | Debug helper that inspects the generated certificates. |
