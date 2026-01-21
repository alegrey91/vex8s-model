# vex8s-model

## Introduction

This repository provides a multi-label machine learning model for automated classification of CVE (Common Vulnerabilities and Exposures) descriptions. The model analyzes vulnerability text and predicts multiple security-related labels, such as arbitrary file write, privilege escalation, resource exhaustion, code execution, and more. It leverages advanced natural language processing techniques—including TF-IDF, stemming, and stopword removal—to extract meaningful features from CVE descriptions. The classifier is designed to assist security researchers and automation systems in quickly identifying the nature of vulnerabilities from textual data, supporting both training and production inference workflows.

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
