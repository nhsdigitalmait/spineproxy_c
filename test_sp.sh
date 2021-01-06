#!/bin/bash
#
#
OPTIONS="-v "
# nb the proxy prefix
#OPTIONS+="--proxy-insecure "

#OPTIONS+=" --tlsv1.1 --tls-max 1.1"
OPTIONS+=" --tlsv1.2 --tls-max 1.2"
#

# bad certs
#ROOT=$HOME/Documents/certs/OpenTest/OpenTestCerts_3

ROOT=$HOME/Documents/certs/OpenTest/OpenTestCerts_4
SUBJECT=vpn-client-1003.opentest.hscic.gov.uk

PAYLOAD="-d '<wsa:MessageID>uuid:2BA6C8AD-097A-11E7-8EF8-738711186A40</wsa:MessageID>'"

SOAPACTION=urn:nhs:names:services:pdsquery/QUPA_IN000005UK030
#SOAPACTION=urn:nhs:names:services:mm/MCCI_IN010000UK13

case $1 in
	ln)
	# NB re edit /etc/hosts after this 
	# secure to non forwarding fromnis

	#TRUST="--proxy-cacert $ROOT/opentest.pem"
	TRUST="--cacert $ROOT/opentest.pem"

	CERTSET="--cert $ROOT/$SUBJECT.cer --key $ROOT/$SUBJECT.key --pass password"
	DEST="https://$SUBJECT:4432"
	;;

	lf)
	# clear to forwarding tonis
	PROXY="-x http://$SUBJECT:4300"
	#local  listener for tonis forwarder test - will return a 404
	DEST=http://192.168.1.112:4302 # me as gpconnect
	;;

	rf)
	# int clear forwarding tonis
	PROXY="-x http://baldricks:4300"
	# int
	DEST=https://10.239.14.26/reliablemessaging/queryrequest # spine 2 INT
	;;

	*)
	echo usage: $0' ln|lf|rf'
	exit
	;;
esac

curl $OPTIONS $PROXY $TRUST $CERTSET --pass password $PAYLOAD -H "soapaction: $SOAPACTION" $DEST

#openssl s_client -connect 192.168.1.112:4432 -tls1_1
