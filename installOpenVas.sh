#Following the steps outlined here: http://g3zarstudios.com/blog/openvas7-on-raspberry-pi/


sudo apt-get install libmicrohttpd-dev libxml2-dev xsltproc libxslt1-dev pkg-config flex cmake libssh-dev sqlite3 libsqlite3-dev libgnutls28-dev libgcrypt11-dev libglib2.0-dev libpcap-dev libgpgme11-dev uuid-dev bison libksba-dev nmap rpm

sudo wget http://wald.intevation.org/frs/download.php/1722/openvas-libraries-7.0.4.tar.gz
sudo wget http://wald.intevation.org/frs/download.php/1726/openvas-scanner-4.0.3.tar.gz
sudo wget http://wald.intevation.org/frs/download.php/1730/openvas-manager-5.0.4.tar.gz
sudo wget http://wald.intevation.org/frs/download.php/1734/greenbone-security-assistant-5.0.3.tar.gz
sudo wget http://wald.intevation.org/frs/download.php/1633/openvas-cli-1.3.0.tar.gz

tar zxf openvas-libraries-7.0.4.tar.gz
tar zxf openvas-scanner-4.0.3.tar.gz
tar zxf openvas-manager-5.0.4.tar.gz
tar zxf greenbone-security-assistant-5.0.3.tar.gz
tar zxf openvas-cli-1.3.0.tar.gz

cd openvas-libraries-7.0.4
mkdir build
cd build
sudo cmake ..
sudo make
sudo make install
sudo make rebuild_cache
sudo make install

cd ../..
cd openvas-scanner-4.0.3
mkdir build
cd build
sudo cmake ..
sudo make
sudo make install
sudo make rebuild_cache
sudo make install

cd ../..
cd openvas-manager-5.0.4
mkdir build
cd build
sudo cmake ..
sudo make
sudo make install
sudo make rebuild_cache
sudo make install

cd ../..
cd greenbone-security-assistant-5.0.3
mkdir build
cd build
sudo cmake ..
sudo make
sudo make install
sudo make rebuild_cache
sudo make install

cd ../..
cd openvas-cli-1.3.0
mkdir build
cd build
sudo cmake ..
sudo make
sudo make install
sudo make rebuild_cache
sudo make install

cd ../..
sudo ldconfig
sudo openvas-mkcert
sudo openvassd
#build in logic to look for waiting for connections from 'ps -aef | grep openvassd
sudo openvasmd —rebuild —progress
sudo openvasmd --update
sudo openvasmd --migrate
sudo openvasmd -rebuild -progress
sudo openvas-scapdata-sync
sudo openvas-certdata-sync
#Add openvassd to start on boot
#Add this to start on boot
sudo gsad --http-only -p 9392

