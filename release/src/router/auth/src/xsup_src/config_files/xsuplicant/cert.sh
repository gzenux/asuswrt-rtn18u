#!/bin/sh
# cert.sh wlan_interface
CERT_CONFIG_FILE="/etc/1x/1x.conf"
#CERT_CONFIG_FILE="./1x.conf"
#PASSWD="realtek"
eval `flash get USER_IDX`
eval `flash get ROOT_IDX`
eval `flash get CERTUSER_TBL_NUM`
eval `flash get CERTROOT_TBL_NUM`
if [ $USER_IDX = 0 -o $ROOT_IDX = 0 -o $CERTUSER_TBL_NUM = 0 -o $CERTROOT_TBL_NUM = 0 ] ;then
exit
fi
if [  $USER_IDX -gt $CERTUSER_TBL_NUM ] && [ $USER_IDX -gt $CERTROOT_TBL_NUM ] ;then
exit
fi
flash cert /etc/1x
PASSWD=`flash get CERTUSER_TBL | grep CERTUSER_TBL$USER_IDX`
USER_CERT=`echo $PASSWD | cut -f2 -d=`
USER_CERT=`echo $USER_CERT | cut -f1 -d,`
PASSWD=`echo $PASSWD |  cut -f2 -d,`

ROOT_CERT=`flash get CERTROOT_TBL| grep CERTROOT_TBL$ROOT_IDX`
ROOT_CERT=`echo $ROOT_CERT | cut -f2 -d=`
openssl pkcs12 -des3 -in /etc/1x/$USER_CERT.pfx -out /etc/1x/user.pem   -passout pass:$PASSWD -passin pass:$PASSWD
openssl x509 -inform PEM -outform DER -in /etc/1x/user.pem -out /etc/1x/user.der
openssl x509 -inform DER -in /etc/1x/$ROOT_CERT.cer -outform PEM -out /etc/1x/root.pem

IDENT=`cat /etc/1x/user.pem  | grep subject | cut -f7 -d"="`
echo "TLS ident =$IDENT"
echo "TLS pass = $PASSWD"
echo "network_list = all"  > $CERT_CONFIG_FILE
echo "default_netname = default" >> $CERT_CONFIG_FILE
echo "default" >> $CERT_CONFIG_FILE
echo "{" >> $CERT_CONFIG_FILE
echo  " type = wireless" >> $CERT_CONFIG_FILE
echo  " allow_types = eap_tls" >>  $CERT_CONFIG_FILE
echo   " identity = <BEGIN_ID>$IDENT<END_ID>"  >> $CERT_CONFIG_FILE
echo   " eap_tls {" >> $CERT_CONFIG_FILE
echo   "    user_cert = /etc/1x/user.der" >> $CERT_CONFIG_FILE
echo  "    user_key  = /etc/1x/user.pem" >> $CERT_CONFIG_FILE
echo   "    user_key_pass = <BEGIN_PASS>$PASSWD<END_PASS>" >> $CERT_CONFIG_FILE
echo   "    root_cert = /etc/1x/root.pem" >> $CERT_CONFIG_FILE
echo   "    chunk_size = 1398" >> $CERT_CONFIG_FILE
echo   "    random_file = /dev/urandom" >> $CERT_CONFIG_FILE
echo   " }" >> $CERT_CONFIG_FILE
echo "}" >> $CERT_CONFIG_FILE
