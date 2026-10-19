# Wazuh Home Lab

A small home lab to learn how a SIEM works. I wanted to follow one event from the Linux machine where it happens to the Wazuh dashboard and understand why a rule fires.

I started with a failed SSH login and a file change. Then I added my own correlation rule and a small Python script to retrieve its alerts. Everything ran on my own VMs.

**Author:** Erdem Yacel · **Test date:** 19 October 2026

## Setup

| Machine | Details |
| --- | --- |
| Windows laptop | 16 GB RAM, VMware Workstation Pro. Runs the VMs, I used PowerShell for SSH |
| Wazuh server | Wazuh 4.14.9 all-in-one OVA, 4 vCPU, 8 GB RAM, 50 GB disk, `192.168.161.128` |
| Ubuntu server | Ubuntu 24.04.5 LTS, 2 vCPU, 2 GB RAM, 20 GB disk, `192.168.161.129`, named `ubuntutest` |
| Wazuh agent | Version 4.14.9, ID `001`, installed on the Ubuntu server |

Both VMs use VMware NAT. The dashboard shows the agent as active.

![Active Ubuntu agent](images/01-agent-active.png)

## 1. Failed SSH login

From Windows I tried to log in with one wrong password:

```powershell
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 erdem@192.168.161.129
```

On Ubuntu I checked the original log with `sudo journalctl -u ssh --since "5 minutes ago" --no-pager`.

![SSH journal](images/02-ssh-source-log.png)

Wazuh collected it from journald, decoded it as sshd and raised rule **5760** (level 5). The user was `erdem` and the source was `192.168.161.1`, the source address recorded for my Windows SSH attempt.

![SSH alerts filtered by source IP](images/03-ssh-alerts.png)

This one attempt created three alerts: PAM failure (`5503`), SSH authentication failure (`5760`) and connection reset (`5762`). So the number of alerts is not the number of login attempts.

If this was not my own test, I would check who owns the source IP, look for attempts on other accounts and check for a successful login afterwards. One failed login alone is not enough to tell whether it was a mistake or an attack.

## 2. File change (FIM)

I created `/opt/wazuh-lab/test.conf` with the text `version=1`. In the `<syscheck>` section of the agent config I added:

```xml
<directories check_all="yes" realtime="yes" report_changes="yes">/opt/wazuh-lab</directories>
```

I made a backup of the config, tested it with `sudo /var/ossec/bin/wazuh-syscheckd -t` and restarted the agent. The agent log showed that the first scan was done and real-time monitoring had started. Then I changed the file:

```bash
echo 'version=2' | sudo tee /opt/wazuh-lab/test.conf
```

![File integrity alert](images/04-fim-alert.png)

Wazuh raised rule **550** (level 7, `Integrity checksum changed.`) and showed the changed hashes and the exact difference.

![Difference and hashes](images/05-fim-diff.png)

Both versions are 10 bytes so it caught a content change even though the size stayed the same. The alert shows the owner `root` but that does not tell me who edited the file. I did not turn on who-data in this lab. In a real case I would look at sudo and audit logs.

## 3. My own rule

I added [rule 100100](rules/ssh-correlation.xml) to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh server. It fires at level 10 when the same source IP has **5 SSH password failures within 120 seconds**. It is based on rule `5760`, so the PAM and connection-reset alerts are not counted. It does not check the username.

I checked the config with `sudo /var/ossec/bin/wazuh-analysisd -t`. In `wazuh-logtest` the first four sample events matched `5760` and the fifth matched `100100`. Then I restarted the manager and made five real wrong-password attempts.

![Custom rule alert](images/06-custom-rule-alert.png)

The alert lists four earlier failures (10:03:10, 10:03:25, 10:03:35, 10:03:45 UTC) and the fifth one at 10:03:55 UTC. That is five failures in 45 seconds.

![Four earlier events and the fifth](images/07-custom-rule-details.png)

This was my own test. Level 10 is just my choice for priority, it does not prove anything bad happened.

## 4. Python script

[fetch_alerts.py](scripts/fetch_alerts.py) uses only the standard library. It asks the Wazuh Indexer API for rule `100100` alerts from agent `001`, prints a short summary and saves the result as JSON. It is the same search I did by hand in the dashboard.

I ran it on the Wazuh server, because the indexer listens on `127.0.0.1:9200`. It checks the TLS certificate with the lab CA and asks for the password with `getpass`, so no password is saved.

Run these commands on the Wazuh server, from the repository root directory:

```bash
mkdir -p ~/wazuh-lab
cp scripts/fetch_alerts.py ~/wazuh-lab/
sudo install -m 644 /etc/wazuh-indexer/certs/root-ca.pem ~/wazuh-lab/root-ca.pem
cd ~/wazuh-lab
python3 fetch_alerts.py
```

It found one alert, with the same time, source, rule and level as the dashboard. The terminal output is in [evidence/python-run.txt](evidence/python-run.txt). Certificates, passwords and the JSON report are not in this repo.

Limits: I run it by hand, it only gets the latest 100 matches, the agent ID and rule ID are written in the code and I used the admin account. A read-only account would be better.

## Problems I ran into

- **Root disk full.** The virtual disk was 50 GB but the root partition was only 25 GB and 100% full. I checked `df` and `lsblk`, then grew the partition with `growpart` and the XFS filesystem with `xfs_growfs`. About 25 GB became free.
- **OVA did not boot on my Ryzen laptop.** The AMD workaround from the Wazuh documentation fixed it.
- **Time zones.** Ubuntu logs use UTC and the dashboard shows UTC+2. For example `10:03:55` UTC shows as `12:03:55` in the dashboard.

## What I took from it

- An active agent is only the first check. Making an event and finding its alert shows that collection and detection both work.
- Alerts and login attempts are not the same thing.
- A correlation rule connects several events over time.
- A small script can repeat a search I did by hand.

## Scope

One endpoint, built-in rules plus one custom rule. I did not test production scale, automatic blocking or scheduled reports.

## AI use

I used AI assistance for setup guidance, the custom rule, the Python script. I ran the commands, analyses and tests on my own VMs and took the screenshots myself.

## References

- [Wazuh virtual machine deployment](https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html)
- [Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [File integrity monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html)
- [Indexer API examples](https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html)
