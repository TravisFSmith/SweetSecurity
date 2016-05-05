# SweetSecurity - Raspberry Pi 3 Edition

Scripts to setup and install Bro IDS, Elastic Search, Logstash, Kibana, and Critical Stack on a Raspberry Pi 3 device.

Fixes:
  * node versus nodejs-legacy package incompatabilities
  * . /etc/init.d/functions updated to . /lib/lsb/init-functions
  * updated logstash version to 2.3.2
  * updated elasticsearch version to 2.3.2
  * fixed logstash.conf to work with new software versions and Pi 3

Outstanding:
  * services not autostarting after install (crashed)
  * BroIDS needs to be deployed manually (broctl deploy & broctl start)
  * email notifications disabled in logstash config, currently erroring on options
  * OpenVAS not yet tested
