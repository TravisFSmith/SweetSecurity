# SweetSecurity

Scripts to setup and install Bro IDS, Elasticsearch, Logstash, Kibana, and Critical Stack on any device.

For more information on installation and how Sweet Security works, see the Wiki:

https://github.com/TravisFSmith/SweetSecurity/wiki

Installation:
  * sudo python setup.py
  * Follow prompts to enter appropriate information for chosen installation type

New Functionality:
  * Modularized Installation - Choose to deploy all the tools on one device, or split among multiple for better performance. 
    * Full Install - Deploy Bro IDS, Critical Stack, Elasticsearch, Logstash, Kibana, Apache, and Sweet Security
    * Sensor Install - Deploy Bro IDS, Critical Stack, Logstash, and Sweet Security
    * Web Admin Install - Deploy Elasticsearch, Kibana, and Apache
  * ARP Spoofing - Full code to monitor all network traffic out of the box without network changes. 
  * Complete Bro Log Support - All Bro log files are now normalized by Logstash
  * Kibana Content - Searches, Visualizations, and Dashboards are now included
  * Architecture Support - Now supports installing on non ARM architectures
  * Custom NMAP Pre-Fix - updated NMAP pre-fixes based on the IEEE OUI list
  * Web Administration - apache/flask based web administration to manage known devices and system health

Fixes:
  * Optimized Logstash Config
  * Updated Bro IDS to 2.5.1
  * Updated Logstash to version 5.5.1
  * Updated Elasticsearch to version 5.5.1
  * Update kibana to version 5.5.1


