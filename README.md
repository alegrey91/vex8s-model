# vex8s-model

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
