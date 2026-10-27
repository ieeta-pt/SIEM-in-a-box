"""Install the measurement ingest pipelines and index template.

Every benchmark index (bench-*) runs `bench-final` as its final pipeline:
it extracts the generator's sequence number and production timestamp from
the raw line and stamps the ingest time, so loss, duplicates and
produce-to-ingest latency are computed identically for every variant.
`nginx-parse` and `auth-parse` reproduce, inside Elasticsearch, the same
parsing that the Logstash pipelines perform (used by the broker-free
variants).
"""
import sys
import requests

ES = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9200"

NGINX_GROK = ('%{IPORHOST:source.ip} - %{DATA:user.name} \\[%{HTTPDATE:nginx.time}\\] '
              '"%{WORD:http.request.method} %{DATA:url.original} HTTP/%{NUMBER:http.version}" '
              '%{NUMBER:http.response.status_code:int} %{NUMBER:http.response.body.bytes:int} '
              '"%{DATA:http.request.referrer}" "%{DATA:user_agent.original}"')
AUTH_GROK = ('%{SYSLOGTIMESTAMP:auth.time} %{SYSLOGHOST:host.name} sshd\\[%{POSINT:process.pid}\\]: '
             'Failed password for (invalid user )?%{USERNAME:user.name} from %{IPORHOST:source.ip} '
             'port %{POSINT:source.port} ssh2')

PIPELINES = {
    "bench-final": {
        "description": "Measurement stamps (seq, produce time, ingest time, latency)",
        "processors": [
            {"set": {"field": "_bench_ingest_ts", "value": "{{{_ingest.timestamp}}}"}},
            {"script": {"lang": "painless", "source": """
                String m = ctx.containsKey('message') ? ctx.message : (ctx.containsKey('full_log') ? ctx.full_log : null);
                if (m == null) { ctx.remove('_bench_ingest_ts'); return; }
                int i = m.indexOf('bseq=');
                if (i < 0) { ctx.remove('_bench_ingest_ts'); return; }
                int j = m.indexOf(':', i);
                int k = j + 1;
                while (k < m.length() && Character.isDigit(m.charAt(k))) { k++; }
                long seq = Long.parseLong(m.substring(i + 5, j));
                long tns = Long.parseLong(m.substring(j + 1, k));
                ZonedDateTime z = ZonedDateTime.parse(ctx._bench_ingest_ts);
                ctx.remove('_bench_ingest_ts');
                long now = z.toEpochSecond() * 1000000000L + z.getNano();
                Map b = new HashMap();
                b.put('seq', seq);
                b.put('t_ns', tns);
                b.put('t_ingest_ns', now);
                b.put('lat_ms', (now - tns) / 1000000.0);
                b.put('src', m.indexOf('sshd[') >= 0 ? 'auth' : 'nginx');
                ctx.bench = b;
            """}}
        ],
    },
    "nginx-parse": {
        "description": "nginx access-log parsing (identical to Logstash nginx.conf)",
        "processors": [
            {"grok": {"field": "message", "patterns": [NGINX_GROK],
                      "on_failure": [{"append": {"field": "tags", "value": "_grokparsefailure"}}]}},
            {"date": {"field": "nginx.time", "formats": ["dd/MMM/yyyy:HH:mm:ss Z"],
                      "ignore_failure": True}},
            {"user_agent": {"field": "user_agent.original", "target_field": "user_agent",
                            "ignore_missing": True}},
        ],
    },
    "auth-parse": {
        "description": "sshd failed-login parsing (identical to Logstash auth.conf)",
        "processors": [
            {"grok": {"field": "message", "patterns": [AUTH_GROK],
                      "on_failure": [{"append": {"field": "tags", "value": "_grokparsefailure"}}]}},
        ],
    },
}

TEMPLATE = {
    "index_patterns": ["bench-*"],
    "priority": 500,
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.final_pipeline": "bench-final",
        },
        "mappings": {
            "properties": {
                "bench": {"properties": {
                    "seq": {"type": "long"},
                    "t_ns": {"type": "long"},
                    "t_ingest_ns": {"type": "long"},
                    "lat_ms": {"type": "double"},
                    "src": {"type": "keyword"},
                }},
            }
        },
    },
}


def main():
    s = requests.Session()
    for name, body in PIPELINES.items():
        r = s.put(f"{ES}/_ingest/pipeline/{name}", json=body)
        r.raise_for_status()
    r = s.put(f"{ES}/_index_template/bench", json=TEMPLATE)
    r.raise_for_status()
    # allow wildcard deletes so per-run cleanup actually frees disk
    r = s.put(f"{ES}/_cluster/settings",
              json={"persistent": {"action.destructive_requires_name": False}})
    r.raise_for_status()
    print("pipelines and template installed")


if __name__ == "__main__":
    main()
