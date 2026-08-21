#!/bin/bash
# Netzwart Export – Check Point mgmt_cli
# Regeln: SR0001
set -e
mgmt_cli login user "$CP_USER" password "$CP_PASSWORD" > session.txt

# --- SR0001: Zugriff Backup auf PROD-APP ---
mgmt_cli add host name "log03.demo.local" ip-address "10.10.90.38" -s session.txt --ignore-warnings true
mgmt_cli add host name "app08.demo.local" ip-address "10.10.30.71" -s session.txt --ignore-warnings true
mgmt_cli add host name "svc11.demo.local" ip-address "10.10.30.31" -s session.txt --ignore-warnings true
mgmt_cli add host name "svc63.demo.local" ip-address "10.10.30.218" -s session.txt --ignore-warnings true
mgmt_cli add service-tcp name "tcp_443" port 443 -s session.txt --ignore-warnings true
mgmt_cli add access-rule layer "Network" position top name "SR0001 Backup-PROD-APP-001" source.1 "log03.demo.local" destination.1 "app08.demo.local" destination.2 "svc11.demo.local" destination.3 "svc63.demo.local" service.1 "tcp_443" action "Accept" -s session.txt

mgmt_cli publish -s session.txt
mgmt_cli logout -s session.txt
