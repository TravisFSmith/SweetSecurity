# SweetSecurity - Raspberry Pi 3 Edition

Scripts to setup and install Bro IDS, Elastic Search, Logstash, Kibana, and Critical Stack on a Raspberry Pi 3 device.

Fixes:
  * node versus nodejs-legacy package incompatabilities
  * . /etc/init.d/functions updated to . /lib/lsb/init-functions
  * updated logstash to version 2.3.2
  * updated elasticsearch to version 2.3.2
  * update kibana to version 4.5.0
  * fixed logstash.conf to work with new software versions and Pi 3

Outstanding:
  * services not autostarting after reboot (crashed)
  * email notifications disabled in logstash config, currently erroring on options
  * OpenVAS not yet tested
