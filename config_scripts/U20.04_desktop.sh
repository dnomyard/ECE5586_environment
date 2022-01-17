# Config script for ECE5586 Ubuntu 20.04 Desktop
#
# Base environment: Ubuntu 20.04 Desktop and Ubuntu 20.04 Terminal (2021.8)
# - Installs Snort/Barnyard2/BASE for IDS exercises
# - Configures 
# https://low-orbit.net/snort-setup
echo "******************************************************"
echo "************ Configuring prerequisites ********************"
sudo apt update -y
sudo apt install -y build-essential automake libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev libnghttp2-dev
sudo apt install -y openssh-server ethtool
# Install/build data acquisition library (DAQ) for Ubuntu 20.04
sudo ln -s /usr/bin/aclocal-1.16 /usr/bin/aclocal-1.15
sudo ln -s /usr/bin/automake-1.16 /usr/bin/automake-1.15
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
tar -zxvf daq-2.0.7.tar.gz
cd daq-2.0.7
./configure && make && sudo make install
# LuaJIT
cd ~
wget http://luajit.org/download/LuaJIT-2.0.2.tar.gz
tar xvfz LuaJIT-2.0.2.tar.gz 
cd LuaJIT-2.0.2/
make
sudo make install
echo "******************************************************"
echo "************       Installing snort              ********************"
cd ~
# wget https://www.snort.org/downloads/snort/snort-2.9.16.tar.gz
wget https://www.snort.org/downloads/snort/snort-2.9.19.tar.gz
tar xvzf snort-2.9.19.tar.gz
cd snort-2.9.19
./configure --enable-sourcefire && make && sudo make install
# ldconfig to update shared libs
sudo ldconfig
# to confirm successful install, at the command line: snort -V
# create snort user and group
sudo groupadd snort 
sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort
# Snort rules and configs
sudo mkdir /etc/snort
sudo mkdir /etc/snort/rules
sudo mkdir /etc/snort/rules/iplists
sudo mkdir /etc/snort/preproc_rules
sudo mkdir /etc/snort/so_rules
sudo mkdir /usr/local/lib/snort_dynamicrules
sudo mkdir /var/log/snort
sudo mkdir /var/log/snort/archived_logs
sudo touch /etc/snort/rules/white_list.rules
sudo touch /etc/snort/black_list.rules
sudo touch /etc/snort/rules/local.rules
sudo touch /etc/snort/sid-msg.map
# edit permissions
sudo chmod -R 5775 /etc/snort/
sudo chmod -R 5775 /var/log/snort/
sudo chmod -R 5775 /usr/local/lib/snort_dynamicrules/
# change ownership
sudo chown -R snort:snort /etc/snort
sudo chown -R snort:snort /var/log/snort
sudo chown -R snort:snort /usr/local/lib/snort_dynamicrules
# copy snort configs to /etc/snort
cd ~/snort-2.9.19/etc
sudo cp *.conf* /etc/snort
sudo cp *.map /etc/snort
sudo cp *.dtd /etc/snort
cd ~/snort-2.9.19/src/dynamic-preprocessors/build/usr/local/lib/snort_dynamicpreprocessor/
sudo cp -avr * /usr/local/lib/snort_dynamicpreprocessor/
# install ruleset
cd ~
## wget https://www.snort.org/downloads/community/community-rules.tar.gz -O community-rules.tar.gz
## sudo tar -xvzf community-rules.tar.gz -C /etc/snort/rules
# download and install ruleset
wget https://github.com/dnomyard/ECE5586_environment/raw/main/artifacts/snort/snortrules.tar.gz
sudo tar -zxf snortrules.tar.gz -C /etc/snort/
# download and install snort.conf
sudo rm /etc/snort/snort.conf
sudo curl https://raw.githubusercontent.com/dnomyard/ECE5586_environment/main/artifacts/snort/snort.conf -o /etc/snort/snort.conf
# Barnyard2
echo "******************************************************"
echo "************       Installing barnyard      ********************"
# install prereqs
sudo apt-get install -y mysql-server libmysqlclient-dev mysql-client autoconf libtool
cd ~/snort-2.9.19
wget https://github.com/firnsy/barnyard2/archive/master.tar.gz -O barnyard2-Master.tar.gz
tar zxvf barnyard2-Master.tar.gz
cd barnyard2-master
autoreconf -fvi -I ./m4
sudo ln -s /usr/include/dumbnet.h /usr/include/dnet.h
sudo ldconfig
./configure --with-mysql --with-mysql-libraries=/usr/lib/x86_64-linux-gnu
# Fixed macro in ~/barnyard2-master/src/output-plugins/spo_alert_fwsam.c for libpcap 1.9 compatibility
# see https://github.com/firnsy/barnyard2/pull/254 and
#        https://github.com/firnsy/barnyard2/pull/254/commits/cc53c5573ba016489518bcda69ca64ca7acee2e8
sed -i "s/SOCKET stationsocket;/BARNYARD2_SOCKET stationsocket;/g" ./src/output-plugins/spo_alert_fwsam.c 
sed -i "s/typedef int SOCKET;/typedef int BARNYARD2_SOCKET;/g" ./src/output-plugins/spo_alert_fwsam.c
# Fixed macro in spo_database.h to build with mysql 8 cient
# see https://github.com/firnsy/barnyard2/issues/252
sed -i "s/    my_bool mysql_reconnect; \/\* We will handle it via the api. \*\//    bool mysql_reconnect; \/\* We will handle it via the api. \*\//g" ./src/output-plugins/spo_database.h
make
sudo make install
#test: /usr/local/bin/barnyard2 -V
sudo cp ~/snort-2.9.19/barnyard2-master/etc/barnyard2.conf /etc/snort/
sudo mkdir /var/log/barnyard2
sudo chown snort:snort /var/log/barnyard2
sudo touch /var/log/snort/barnyard2.waldo
sudo chown snort:snort /var/log/snort/barnyard2.waldo
sudo mysql -e "CREATE DATABASE snort;"
# sudo mysql -e "USE snort;"
# sudo mysql -e "CREATE USER snort@localhost IDENTIFIED BY 'Sn0rtD@t@B@seP@ssw0rd';"
# see https://medium.com/@crmcmullen/how-to-run-mysql-8-0-with-native-password-authentication-502de5bac661
sudo mysql -e "CREATE USER snort@localhost IDENTIFIED WITH mysql_native_password BY 'Sn0rtD@t@B@seP@ssw0rd';"
sudo mysql -e "GRANT ALL PRIVILEGES ON snort.* TO snort@localhost;"
sudo mysql -u snort -pSn0rtD@t@B@seP@ssw0rd -D snort -e "SOURCE /home/student/snort-2.9.19/barnyard2-master/schemas/create_mysql;"
# see https://medium.com/@crmcmullen/how-to-run-mysql-8-0-with-native-password-authentication-502de5bac661
echo -e "[mysqld]\ndefault-authentication-plugin=mysql_native_password" | sudo tee -a /etc/mysql/my.cnf
echo "output database: log, mysql, user=snort password=Sn0rtD@t@B@seP@ssw0rd dbname=snort host=localhost sensor name=sensor01" | sudo tee -a /etc/snort/barnyard2.conf 
sudo chmod o-r /etc/snort/barnyard2.conf
sudo chown snort /etc/snort/barnyard2.conf
sudo chgrp snort /etc/snort/barnyard2.conf
# restart mysql to accept modified settings
sudo service mysql restart
# test? sudo /usr/local/bin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i eth0 -D
### set up systemD services for snort and barnyard2
# setup snort service
sudo touch /lib/systemd/system/snort.service
echo "[Unit]" | sudo tee -a /lib/systemd/system/snort.service
echo "   Description=Snort NIDS Daemon" | sudo tee -a /lib/systemd/system/snort.service
echo "   After=syslog.target network.target" | sudo tee -a /lib/systemd/system/snort.service
echo "[Service]" | sudo tee -a /lib/systemd/system/snort.service
echo "   Type=simple" | sudo tee -a /lib/systemd/system/snort.service
echo "   ExecStart=/usr/local/bin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i eth0" | sudo tee -a /lib/systemd/system/snort.service
echo "[Install]" | sudo tee -a /lib/systemd/system/snort.service
echo "  WantedBy=multi-user.target" | sudo tee -a /lib/systemd/system/snort.service
sudo systemctl enable snort
sudo systemctl start snort
# setup barnyard as a service
sudo touch /lib/systemd/system/barnyard2.service
echo "[Unit]" | sudo tee -a /lib/systemd/system/barnyard2.service
echo "   Description=Barnyard2 Daemon" | sudo tee -a /lib/systemd/system/barnyard2.service
echo "   After=syslog.target network.target" | sudo tee -a /lib/systemd/system/barnyard2.service
echo "[Service]" | sudo tee -a /lib/systemd/system/barnyard2.service
echo "   Type=simple" | sudo tee -a /lib/systemd/system/barnyard2.service
# echo "   User=snort" | sudo tee -a /lib/systemd/system/barnyard2.service
# echo "   Group=snort" | sudo tee -a /lib/systemd/system/barnyard2.service
# Next 3 lines are to fix error described here: https://disloops.com/fixing-the-barnyard2-pid-file-problem/
echo "   PermissionsStartOnly=true" | sudo tee -a /lib/systemd/system/barnyard2.service
echo "   ExecStartPre=-/bin/mkdir /var/run/snort" | sudo tee -a /lib/systemd/system/barnyard2.service
echo "   ExecStartPre=/bin/chown -R snort:snort /var/run/snort/" | sudo tee -a /lib/systemd/system/barnyard2.service
echo "   ExecStart=/usr/local/bin/barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.u2 -q -w /var/log/snort/barnyard2.waldo -g snort -D -a /var/log/snort/archived_logs --pid-path=/var/run/snort" | sudo tee -a /lib/systemd/system/barnyard2.service
echo "[Install]" | sudo tee -a /lib/systemd/system/barnyard2.service
echo "   WantedBy=multi-user.target" | sudo tee -a /lib/systemd/system/barnyard2.service
# enable and start service
sudo systemctl enable barnyard2
sudo systemctl start barnyard2
# BASE
echo "******************************************************"
echo "************            Installing BASE         ********************"
sudo add-apt-repository ppa:ondrej/php -y
# sudo apt-get update
sudo apt-get install -y apache2 libapache2-mod-php5.6 php5.6-mysql php5.6-cli php5.6 php5.6-common php5.6-gd php5.6-cli php-pear php5.6-xml
# Pear image graph
sudo pear install -f --alldeps Image_Graph
# ADODB
cd ~
wget https://sourceforge.net/projects/adodb/files/adodb-php5-only/adodb-520-for-php5/adodb-5.20.9.tar.gz
tar -xvzf adodb-5.20.9.tar.gz
sudo mv adodb5 /var/adodb
sudo chmod -R 755 /var/adodb
cd ~
wget http://sourceforge.net/projects/secureideas/files/BASE/base-1.4.5/base-1.4.5.tar.gz
tar xzvf base-1.4.5.tar.gz
sudo mv base-1.4.5 /var/www/html/base/
cd /var/www/html/base
sudo cp base_conf.php.dist base_conf.php
# configure vi /var/www/html/base/base_conf.php
sudo sed -i "s/\$BASE_urlpath = '';/\$BASE_urlpath = '\/base';/" /var/www/html/base/base_conf.php
sudo sed -i "s/\$DBlib_path = '';/\$DBlib_path = '\/var\/adodb\/';/" /var/www/html/base/base_conf.php
sudo sed -i "s/\$alert_dbname   = 'snort_log';/\$alert_dbname     = 'snort';/" /var/www/html/base/base_conf.php
sudo sed -i "s/\$alert_password = 'mypassword';/\$alert_password   = 'Sn0rtD@t@B@seP@ssw0rd';/" /var/www/html/base/base_conf.php
sudo sed -i "s/\$graph_font_name = \"DejaVuSans\";/\/\/ \$graph_font_name = \"DejaVuSans\";/" /var/www/html/base/base_conf.php
sudo sed -i "s/\/\/ \$graph_font_name = \"\";/\$graph_font_name = \"\";/" /var/www/html/base/base_conf.php
sudo chown -R www-data:www-data /var/www/html/base
sudo chmod o-r /var/www/html/base/base_conf.php
sudo service apache2 restart
cd ~
# Barnyard2 not always starting on system reboot. Bashrc entry will hopefully correct this
echo "sudo service barnyard2 restart" >> ~/.bashrc
# Software and config for password lab: John the Ripper
sudo apt -y install john
# Config for buffer overflow lab: disable ASLR; allow 32-bit program execution; install binutils (objdupm)
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
sudo touch /etc/sysctl.d/01-disable-aslr.conf
echo "kernel.randomize_va_space = 0" | sudo tee -a /etc/sysctl.d/01-disable-aslr.conf
sudo dpkg --add-architecture i386
sudo apt update
sudo apt -y install libc6:i386 libstdc++6:i386 libncurses5:i386 zlib1g:i386
sudo apt -y install binutils
sudo apt -y install python2
alias python="/usr/bin/python2.7"
echo "alias python=/usr/bin/python2.7" >> ~/.bashrc
# Install Bless hex editor (for crypto lab)
sudo apt -y install bless
sudo apt -y install okteta
# Install nomacs image viewer (for crypto lab - latest Ristretto version is not compatible with .BMP files)
sudo apt -y install nomacs
sudo apt -y remove ristretto
# Install wireshark (silent install; allow student account to access eth0)
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt -y install wireshark
sudo groupadd wireshark
sudo usermod -a -G wireshark student
sudo chgrp wireshark /usr/bin/dumpcap
sudo chmod 750 /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo getcap /usr/bin/dumpcap
# Create folders and place artifacts
wget https://github.com/dnomyard/ECE5586_environment/raw/main/artifacts/lab_files/lab1/buffer_oflow.tar -P /home/student/lab1/
wget https://raw.githubusercontent.com/dnomyard/ECE5586_environment/main/artifacts/lab_files/lab1/user_hashes.txt -P /home/student/lab1/
sudo wget https://raw.githubusercontent.com/dnomyard/ECE5586_environment/main/artifacts/lab_files/lab2/default_firewall.sh -P /etc/
sudo wget https://raw.githubusercontent.com/dnomyard/ECE5586_environment/main/artifacts/lab_files/lab2/extingui.sh -P /etc/
wget https://raw.githubusercontent.com/dnomyard/ECE5586_environment/main/artifacts/lab_files/lab2/firewall.sh -P /home/student/lab2/
sudo chmod +x /etc/default_firewall.sh
sudo chmod +x /etc/extingui.sh
chmod +x /home/student/lab2/firewall.sh
sudo cp /home/student/lab2/firewall.sh /etc/
wget https://github.com/dnomyard/ECE5586_environment/raw/main/artifacts/lab_files/lab2/theft.pcap -P /home/student/lab2/
wget https://github.com/dnomyard/ECE5586_environment/raw/main/artifacts/lab_files/lab2/illauth.pcap -P /home/student/lab2/
wget https://github.com/dnomyard/ECE5586_environment/raw/main/artifacts/lab_files/lab3/shapes.bmp -P /home/student/lab3/
wget https://raw.githubusercontent.com/dnomyard/ECE5586_environment/main/artifacts/lab_files/lab3/plain.txt -P /home/student/lab3/
wget https://raw.githubusercontent.com/dnomyard/ECE5586_environment/main/artifacts/lab_files/lab3/test_message.txt -P /home/student/lab3/

#########################
## minor cleanup        #
cd ~
sudo rm *.gz
sudo rm *.sh
history -c

