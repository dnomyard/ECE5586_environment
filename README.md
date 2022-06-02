# Config scripts and artifacts for Ubuntu w/Snort and Other Tools environment.

## Config Scripts

This environment supports hands-on labs that are included in the Cyber Range courseware repository (and used in VT's ECE5586 course).

Base environment is Ubuntu 20.04 Desktop and Ubuntu 20.04 Terminal (2021.8)

### ./config_scripts/U20.04_desktop.sh

Applied to Ubuntu 20.04 Desktop VM. Installs Snort/Barnyard/BASE for Cyber Range IDS exercises. Also installs artifacts for the following labs:
- ECE5586 Lab 1: password cracking and buffer overflow
- ECE5586 Lab 2: firewall configuration and intrusion detection
- ECE5586 Lab 3: block cipher modes of operation

### ./config_scripts/U20.04_terminal.sh

Applied to Ubuntu 20.04 Terminal VM. Installs apache web server for testing firewall configuration lab.

## Artifacts

- /lab_files: File artifacts for labs listed above
- /snort: Snort config file and ruleset to support intrusion detection lab


