# DIESES SKRIPT MUSS AUS DEM VERZEICHNIS AUSGEFÜHRT WERDEN!
#basierend auf https://upcloud.com/community/tutorials/install-snort-ubuntu/
set -e
err_report() {
    echo "Error on line $1"
}

trap 'err_report $LINENO' ERR

# bei Fehler abbrechen
#set -e
# Verwende google-nameserver, andere machen Probleme
#sudo sed -ir 's/[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/8.8.8.8/g' /etc/resolv.conf

. config
sudo apt update
sudo apt install -y gcc libpcre3-dev zlib1g-dev libpcap-dev openssl libssl-dev libnghttp2-dev libdumbnet-dev bison flex libdnet luajit
sudo mkdir snort_src 
#installiere data acquisition library
wget -P ~ https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz
tar -xvzf ~/daq-2.0.6.tar.gz
cd daq-2.0.6
./configure && make && sudo make install
cd ../snort_src
sudo wget https://www.snort.org/downloads/snort/snort-2.9.13.tar.gz
sudo tar -xvzf snort-2.9.13.tar.gz
cd snort-2.9.13
#HIER Geht etwas schief! /etc/ wird nicht nach /etc/snort kopiert!
sudo ./configure --disable-open-appid --enable-sourcefire && sudo make && sudo make install
sudo ldconfig

#ist das nötig? kann auskommentiert werden?
#sudo cp -r ~/snort_src/snort-2.9.13/etc/* /etc/snort

#symbolischer link nach sbin
sudo ln -s /usr/local/bin/snort /usr/sbin/snort
#erstelle unpriviligierten Nutzer auf dem Daemon laufen kann
sudo groupadd snort
sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort

sudo mkdir -p /etc/snort/rules
sudo mkdir /var/log/snort
sudo mkdir /usr/local/lib/snort_dynamicrules

#setze alle Rechte für den neuen Nutzer
sudo chmod -R 5775 /etc/snort
sudo chmod -R 5775 /var/log/snort
sudo chmod -R 5775 /usr/local/lib/snort_dynamicrules
sudo chown -R snort:snort /etc/snort
sudo chown -R snort:snort /var/log/snort
sudo chown -R snort:snort /usr/local/lib/snort_dynamicrules

sudo touch /etc/snort/rules/white_list.rules
sudo touch /etc/snort/rules/black_list.rules
sudo touch /etc/snort/rules/local.rules

sudo mkdir /etc/snort/etc/
sudo cp etc/*.conf* /etc/snort/etc
sudo cp etc/*.map /etc/snort/etc

#DL für community-rules: <- FUNKTIONIRET NICHT BEIM DEPLOYMENT, TODo
#wget https://www.snort.org/rules/community -O ~/community.tar.gz
#mkdir ~/community-rules
#sudo tar -xvf ~/community.tar.gz -C ~/community-rules/
#sudo cp -r ~/community-rules/community-rules/* /etc/snort/rules

#DL für Subscriber-Rules:
#kann das auskommentiert werden wgn. pulledpork?
cd ../..
wget https://www.snort.org/rules/snortrules-snapshot-29130.tar.gz?oinkcode=$OINK_CODE -O ~/subscriber.tar.gz
mkdir ~/subscriber-rules
sudo tar -xvf ~/subscriber.tar.gz -C ~/subscriber-rules
sudo cp -r ~/subscriber-rules/* /etc/snort/etc

#todo: konfiguriere netzwerk-interface sinnvoll, verwende Variablen + if/elses
#Definiere output für Snort-Log als syslog auf local5
#TODO:
####WICHTIG####: LOCAL5 in snort.conf schreiben!!!
#in snort.conf LINE !!!!!!!!!325!!!!!!!!!! auskommentieren
sudo touch /etc/rsyslog.d/snort_syslog.conf

#
sudo chmod 777 /etc/rsyslog.d/snort_syslog.conf
sudo echo "local5.* @$MY_IP:1514;RSYSLOG_SyslogProtocol23Format" >> /etc/rsyslog.d/snort_syslog.conf

#starte Snort (community-rules)
#sudo /usr/sbin/snort -dev -v -c /etc/snort/

#starte Snort (subscriber-rules)
#Logging kann aktiviert werden (var/log/snort/..) in snort.conf als pcap
#in snort.conf LINE !!!!!!!!!326!!!!!!!!!! auskommentieren
#sudo /usr/sbin/snort -dev -v -c /etc/snort/etc/snort.conf


#kommentiere Zeile 325/326 (führt zu bugs)
sudo sed -i '/decompress_swf/s/^/#/g' /etc/snort/etc/snort.conf

#kommentiere alle Rule-Paths
sudo sed -i '/\include \$RULE_PATH/s/^/#/g' /etc/snort/etc/snort.conf

#füge snort.rules ein
sudo sed -i '/# site specific rules/a \include $RULE_PATH\/snort.rules' /etc/snort/etc/snort.conf

#Syslog-Daemon muss am Ende restartet werden, damit Änderungen übernommen werden
sudo service rsyslog restart

#entkommentiere alle preproc_rule_paths 
sudo sed -i '/# include $SO_RULE_PATH/s/^#//g' /etc/snort/etc/snort.conf    
sudo sed -i '/# dynamicdetection directory/s/^#//g' /etc/snort/etc/snort.conf    
#TODO: so_rule_path ist falsch -> aus ../so_rules muss rules werden

#kommentiere alle so_rules die  legacy sind
sudo sed -i '/^# legacy dynamic/,/^# Event/ s/include/# include/g' /etc/snort/etc/snort.conf


#hier werden nochmal alle + zusätzliche rules gezogen & konfiguriert
sudo apt-get -y install libwww-perl

git clone https://github.com/shirkdog/pulledpork.git
cp pulledpork.conf pulledpork/etc/pulledpork.conf
cp disablesid.conf pulledpork/etc/disablesid.conf
cp enablesid.conf pulledpork/etc/enablesid.conf
sudo sed -i "s/OINKCODE/$OINK_CODE/g" ~/pulledpork/etc/pulledpork.conf

cd pulledpork
sudo ./pulledpork.pl -c etc/pulledpork.conf -P -i etc/disablesid.conf -e etc/enablesid.conf

#Sollen andere Variablen in snort.conf noch gesetzt werden?
sudo sed -i "s@ipvar HOME_NET any@ipvar HOME_NET $HOME_NET@g" /etc/snort/etc/snort.conf

#setze local5 als output von alert-logs
sudo sed -i "s/# output alert_syslog: LOG_AUTH LOG_ALERT/output alert_syslog: log_local5/g" /etc/snort/etc/snort.conf


#snort starten (rcap lesen) und zu graylog: sudo /usr/sbin/snort -v -c /etc/snort/rules/snort.conf -A full
#alerts stehen dann in /var/log/snort/alert
#snort starten (rcap lesen) und lokal auswerten: sudo /usr/sbin/snort -v -c /etc/snort/rules/snort.conf -r ~/monday.pcap 
