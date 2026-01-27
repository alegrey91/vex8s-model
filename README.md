# vex8s-model

## Introduction

This repository provides a multi-label machine learning model for automated classification of CVE (Common Vulnerabilities and Exposures) descriptions.
The model analyzes vulnerability text and predicts multiple security-related labels, such as `arbitrary_file_write`, `system_privileges_escalation`, `resource_exhaustion`, and more.

It leverages advanced natural language processing techniques (including TF-IDF, stemming, and stopword removal) to extract meaningful features from CVE descriptions. The classifier is designed to assist security researchers and automation systems in quickly identifying the nature of vulnerabilities from textual data, supporting both training and production inference workflows.

## Classification

The model is trained to predict the following *exploitation categories*:

| Category | Description |
|------------------------|--|
| `arbitrary_file_write` | The ability for an attacker to create or modify files at attacker-controlled paths on the target system, potentially leading to code execution, data corruption, or persistence by overwriting configuration, binaries, or sensitive files. |
| `arbitrary_file_read` | The ability for an attacker to read files from arbitrary locations on the target system, allowing exposure of sensitive information such as credentials, configuration files, source code, or system data. |
| `system_privileges_escalation` | A vulnerability that allows an attacker to gain higher privileges at the operating system or kernel level, typically escalating from an unprivileged user to administrative or root access. |
| `application_privileges_escalation` | A flaw that allows an attacker to gain higher privileges within the context of an application, such as escalating from a normal user to an admin role, bypassing authorization checks without gaining OS-level privileges. |
| `resource_exhaustion` | A condition where an attacker can intentionally consume excessive system or application resources (CPU, memory), leading to degraded performance or denial of service. |

## Setup

```
source .venv/bin/activate
pip install -r requirements.txt
```

## Useful commands

```
# find potential arbitrary_file_write_access
grep -rnw ~/Downloads/cvelistV5-main/cves/202*/ -e "file \(write\|creation\|deletion\|overwrite\)" -l | \
    xargs cat | \
    jq '.containers.cna.descriptions[] | select(.lang=="en") | .value' | \
    shuf -n 100 | \
    xclip -sel clipboard

# find potential resource_exhaustion
grep -rnw ~/Downloads/cvelistV5-main/cves/202*/ -e "DoS" -l | \
    xargs cat | \
    jq '.containers.cna.descriptions[] | select(.lang=="en") | .value' | \
    shuf -n 50 | \
    xclip -sel clipboard
grep -rnw ~/Downloads/cvelistV5-main/cves/202*/ -e "denial of service" -l | \
    xargs cat | \
    jq '.containers.cna.descriptions[] | select(.lang=="en") | .value' | \
    shuf -n 50 | \
    xclip -sel clipboard

# find vulnerabilities description to fill the dataset
cat ~/Downloads/cvelistV5-main/cves/2023/2xxx/* | \
    jq '.containers.cna.descriptions[] | select(.lang=="en") | .value' | \
    xclip -sel clipboard
```
