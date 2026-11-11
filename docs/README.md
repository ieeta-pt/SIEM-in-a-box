# SIEM-in-a-Box: Technical Documentation

This folder holds the technical reference for SIEM-in-a-Box. The project overview and quick start are in the [main README](../README.md); the promotional website is [`index.html`](index.html), served with GitHub Pages from this folder.

| Document | Content |
| --- | --- |
| [Architecture](architecture.md) | Layers, containers, startup order, ports and persistent volumes. |
| [Log pipeline](log-pipeline.md) | How an event travels end to end, Kafka topics and indices, the Logstash pipelines and how to add a new source. |
| [Collectors](collectors.md) | Filebeat, Winlogbeat and rsyslog configurations for each supported source. |
| [Fleet and Terraform](fleet-terraform.md) | Fleet Server, Elastic Agent policies and the Terraform that manages them. |
| [Configuration and operations](configuration.md) | `stack/.env`, Makefile targets, helper scripts and production hardening. |
| [Evaluation](../evaluation/README.md) | Research questions, results, the 269 runs and the measurement harness. |
