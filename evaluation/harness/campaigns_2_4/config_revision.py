"""Render isolated Logstash configurations for the new campaign.

The original configuration files are only read. Separate and shared modes
use byte-identical parser blocks extracted from the existing pipelines.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1]
ORIGINAL = BENCH / "configs/logstash/pipeline"


def filter_body(source: str) -> str:
    content = (ORIGINAL / f"{source}.conf").read_text()
    return content.split("filter {", 1)[1].split("\n}\noutput {", 1)[0].strip("\n")


def shared_pipeline() -> str:
    nginx = "\n".join("    " + line for line in filter_body("nginx").splitlines())
    auth = "\n".join("    " + line for line in filter_body("auth").splitlines())
    return f'''# Shared-topic/shared-pipeline ablation; parsers copied from A-sep.
input {{
  kafka {{
    bootstrap_servers => "kafka:9092"
    topics => ["bench-shared"]
    group_id => "ls-shared"
    codec => json
    auto_offset_reset => "earliest"
    consumer_threads => 2
  }}
}}
filter {{
  if [fields][source] == "nginx" {{
{nginx}
  }} else if [fields][source] == "auth" {{
{auth}
  }} else {{
    mutate {{ add_tag => ["_unknown_bench_source"] }}
  }}
}}
output {{
  elasticsearch {{
    hosts => ["http://es:9200"]
    index => "bench-%{{[fields][run]}}-%{{[fields][source]}}"
    manage_template => false
    data_stream => false
    ecs_compatibility => disabled
  }}
}}
'''


def joined_pipeline() -> str:
    """Factorial cell: separate topics, one shared pipeline (3 workers, 2 consumer threads)."""
    return shared_pipeline().replace(
        "# Shared-topic/shared-pipeline ablation; parsers copied from A-sep.",
        "# Separate-topics/shared-pipeline factorial cell; parsers copied from A-sep.").replace(
        'topics => ["bench-shared"]', 'topics => ["bench-nginx", "bench-auth"]').replace(
        'group_id => "ls-shared"', 'group_id => "ls-joined"')


def filtered_pipeline(source: str) -> str:
    """Factorial cell: one shared topic, one pipeline per source that drops the other source."""
    body = "\n".join("  " + line for line in filter_body(source).splitlines())
    return f'''# Shared-topic/separate-pipelines factorial cell for {source}; parser copied from A-sep.
input {{
  kafka {{
    bootstrap_servers => "kafka:9092"
    topics => ["bench-shared"]
    group_id => "ls-{source}"
    codec => json
    auto_offset_reset => "earliest"
    consumer_threads => 1
  }}
}}
filter {{
  if [fields][source] != "{source}" {{
    drop {{ }}
  }}
{body}
}}
output {{
  elasticsearch {{
    hosts => ["http://es:9200"]
    index => "bench-%{{[fields][run]}}-{source}"
    manage_template => false
    data_stream => false
    ecs_compatibility => disabled
  }}
}}
'''


PIPELINE_IDS = {"A-sep": ("nginx", "auth"), "A-shared": ("shared",),
                "A-topics": ("joined",), "A-pipelines": ("nginx", "auth")}
TOPICS = {"A-sep": (("bench-nginx", 1), ("bench-auth", 1)), "A-topics": (("bench-nginx", 1), ("bench-auth", 1)),
          "A-shared": (("bench-shared", 2),), "A-pipelines": (("bench-shared", 2),)}


def render(variant: str, directory: Path) -> dict[str, str]:
    if variant not in PIPELINE_IDS:
        raise ValueError(f"No Logstash pipeline for {variant}")
    directory.mkdir(parents=True, exist_ok=False)
    pipeline_dir = directory / "pipeline"
    pipeline_dir.mkdir()
    if variant == "A-sep":
        contents = {
            "nginx.conf": (ORIGINAL / "nginx.conf").read_text(),
            "auth.conf": (ORIGINAL / "auth.conf").read_text(),
        }
        pipelines = '''- pipeline.id: nginx
  path.config: "/usr/share/logstash/pipeline/nginx.conf"
  pipeline.workers: 2
  pipeline.batch.size: 125
- pipeline.id: auth
  path.config: "/usr/share/logstash/pipeline/auth.conf"
  pipeline.workers: 1
  pipeline.batch.size: 125
'''
    elif variant == "A-shared":
        contents = {"shared.conf": shared_pipeline()}
        pipelines = '''- pipeline.id: shared
  path.config: "/usr/share/logstash/pipeline/shared.conf"
  pipeline.workers: 3
  pipeline.batch.size: 125
'''
    elif variant == "A-topics":
        contents = {"joined.conf": joined_pipeline()}
        pipelines = '''- pipeline.id: joined
  path.config: "/usr/share/logstash/pipeline/joined.conf"
  pipeline.workers: 3
  pipeline.batch.size: 125
'''
    else:  # A-pipelines: shared topic, one pipeline per source, same 2+1 workers as A-sep
        contents = {"nginx.conf": filtered_pipeline("nginx"), "auth.conf": filtered_pipeline("auth")}
        pipelines = '''- pipeline.id: nginx
  path.config: "/usr/share/logstash/pipeline/nginx.conf"
  pipeline.workers: 2
  pipeline.batch.size: 125
- pipeline.id: auth
  path.config: "/usr/share/logstash/pipeline/auth.conf"
  pipeline.workers: 1
  pipeline.batch.size: 125
'''
    for filename, content in contents.items():
        (pipeline_dir / filename).write_text(content)
    (directory / "pipelines.yml").write_text(pipelines)
    paths = [directory / "pipelines.yml", *sorted(pipeline_dir.iterdir())]
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths}
