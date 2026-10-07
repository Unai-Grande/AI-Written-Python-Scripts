# AI-Written-Python-Scripts
A collection of some NOC monitoring and reporting scripts (Nagios/NagVis scraping, source comparison, and report emailing), written with Claude Code. I designed, tested and validated them against a live environment, and they were either shared with the people who needed them or put into daily use. Perchance. 

Environment specific values such as IPs, hostnames, email addresses, dashboard mappings and so on, have been replaced with placeholders. Do edit the config sections before running.

## Info for scripts starts here
**lookup_nagios_delta.py** – Compares the monitoring system against the
inventory file and sorts every host/service into missing, mismatched, or
identical. This is the tool described in my application.

## Other scripts
- **lookup_nagios_delta.py** – Collects hosts and services from Nagios and then compares them with baseline inventory.
- **send_exclusive_hosts_email.py** – Emails the weekly report and warns if the data is stale.
