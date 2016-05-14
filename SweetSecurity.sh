#software versions
bro_version=2.4.1
elasticsearch_version=2.3.2
logstash_version=2.3.2-1
kibana_version=4.5.0

echo "Please enter your Critical Stack API Key: "
read cs_api

read -p "Enter SMTP Host (smtp.google.com): " smtpHost
smtpHost=${smtpHost:-smtp.google.com}

read -p "Enter SMTP Port (587): " smtpPort
smtpPort=${smtpPort:-587}

read -p "Enter Email Address (email@gmail.com): " emailAddr
emailAddr=${emailAddr:-email@google.com}

read -p "Enter Email Password (P@55word): " emailPwd
emailPwd=${emailPwd:-P@55word}




cd /home/pi

echo "Installing Pre-Requisites..."
sudo apt-get -y install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev ant zip nmap



#Install Bro
echo "Installing Bro"
sudo wget https://www.bro.org/downloads/release/bro-$bro_version.tar.gz
sudo tar -xzf bro-$bro_version.tar.gz
sudo mkdir -p /opt/nsm/bro
cd bro-$bro_version
sudo ./configure --prefix=/opt/nsm/bro
sudo make
sudo make install
cd ..
sudo rm bro-$bro_version.tar.gz
sudo rm -rf bro-$bro_version


#Install Critical Stack
echo "Installing Critical Stack Agent"
sudo wget https://intel.criticalstack.com/client/critical-stack-intel-arm.deb
sudo dpkg -i critical-stack-intel-arm.deb
sudo -u critical-stack critical-stack-intel api $cs_api
sudo rm critical-stack-intel-arm.deb

cd /home/pi

#Install ElasticSearch
echo "Installing Elastic Search"
sudo wget https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-$elasticsearch_version.deb
sudo dpkg -i elasticsearch-$elasticsearch_version.deb
sudo rm elasticsearch-$elasticsearch_version.deb
sudo update-rc.d elasticsearch defaults


#Install LogStash
echo "Installing Logstash"
sudo wget https://download.elastic.co/logstash/logstash/packages/debian/logstash_${logstash_version}_all.deb
sudo dpkg -i logstash_${logstash_version}_all.deb
sudo rm logstash_${logstash_version}_all.deb
cd /home/pi
sudo git clone https://github.com/jnr/jffi.git
cd jffi
sudo ant jar
sudo cp build/jni/libjffi-1.2.so /opt/logstash/vendor/jruby/lib/jni/arm-Linux
cd /opt/logstash/vendor/jruby/lib
sudo zip -g jruby-complete-1.7.11.jar jni/arm-Linux/libjffi-1.2.so
cd /home/pi
sudo rm -rf jffi/
sudo update-rc.d logstash defaults
sudo /opt/logstash/bin/plugin install logstash-filter-translate
sudo cp SweetSecurity/logstash.conf /etc/logstash/conf.d
sudo mkdir /etc/logstash/custom_patterns
sudo cp SweetSecurity/bro.rule /etc/logstash/custom_patterns
sudo mkdir /etc/logstash/translate

#Install Kibana
echo "Installing Kibana"
sudo wget https://download.elastic.co/kibana/kibana/${kibana_version}-linux-x86.tar.gz
sudo tar -xzf kibana-${kibana_version}-linux-x86.tar.gz
sudo mv kibana-${kibana_version}-linux-x86/ /opt/kibana/
sudo apt-get -y remove nodejs-legacy nodejs nodered		#Remove nodejs on Pi3
sudo wget http://node-arm.herokuapp.com/node_latest_armhf.deb
sudo dpkg -i node_latest_armhf.deb
sudo mv /opt/kibana/node/bin/node /opt/kibana/node/bin/node.orig
sudo mv /opt/kibana/node/bin/npm /opt/kibana/node/bin/npm.orig
sudo ln -s /usr/local/bin/node /opt/kibana/node/bin/node
sudo ln -s /usr/local/bin/npm /opt/kibana/node/bin/npm
sudo rm node_latest_armhf.deb
sudo cp SweetSecurity/init.d/kibana /etc/init.d
sudo chmod 755 /etc/init.d/kibana
sudo update-rc.d kibana defaults

#Configure Sweet Security Scripts
sudo mkdir /opt/SweetSecurity
sudo cp SweetSecurity/pullMaliciousIP.py /opt/SweetSecurity/
sudo cp SweetSecurity/pullTorIP.py /opt/SweetSecurity/
#Run scripts for the first time
sudo python /opt/SweetSecurity/pullTorIP.py
sudo python /opt/SweetSecurity/pullMaliciousIP.py

#Configure Logstash Conf File
sudo sed -i -- "s/SMTP_HOST/"$smtpHost"/g" /opt/logstash/logstash.conf
sudo sed -i -- "s/SMTP_PORT/"$smtpPort"/g" /opt/logstash/logstash.conf
sudo sed -i -- "s/EMAIL_USER/"$emailAddr"/g" /opt/logstash/logstash.conf
sudo sed -i -- "s/EMAIL_PASS/"$emailPwd"/g" /opt/logstash/logstash.conf


cd /home/pi
sudo cp SweetSecurity/networkDiscovery.py /opt/SweetSecurity/networkDiscovery.py
sudo cp SweetSecurity/SweetSecurityDB.py /opt/SweetSecurity/SweetSecurityDB.py
#Configure Network Discovery Scripts
sudo sed -i -- "s/SMTP_HOST/"$smtpHost"/g" /opt/SweetSecurity/networkDiscovery.py
sudo sed -i -- "s/SMTP_PORT/"$smtpPort"/g" /opt/SweetSecurity/networkDiscovery.py
sudo sed -i -- "s/EMAIL_USER/"$emailAddr"/g" /opt/SweetSecurity/networkDiscovery.py
sudo sed -i -- "s/EMAIL_PASS/"$emailPwd"/g" /opt/SweetSecurity/networkDiscovery.py


#Restart services
echo "Restarting ELK services"
sudo service elasticsearch restart
sudo service kibana restart
sudo service logstash restart


#Deploy and start BroIDS
echo "Deploying and starting BroIDS"
sudo /opt/nsm/bro/bin/broctl deploy
sudo /opt/nsm/bro/bin/broctl start
