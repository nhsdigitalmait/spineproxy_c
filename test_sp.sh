#!/bin/bash
# exercises the spineproxy
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

# for fromnis to accepts a message it MUST contain a case insensitive match with :messageid
# see session.c line 700 otherwise we get
# Timing out fromnis session from 127.0.0.1 to vpn-client-1003.opentest.hscic.gov.uk:4432 MsgId: UNKNOWN: Connection timed out
# Error logging remaining data: Bad file descriptor
# Logfile close: Bad file descriptor

PAYLOAD="-d '<wsa:MessageID>uuid:2BA6C8AD-097A-11E7-8EF8-738711186A40</wsa:MessageID>'"

SOAPACTION=urn:nhs:names:services:pdsquery/QUPA_IN000005UK030
#SOAPACTION=urn:nhs:names:services:mm/MCCI_IN010000UK13

CP=B82617/STU3/1/gpconnect/fhir

case $1 in
	ln)
	# NB re edit /etc/hosts after this 
	# secure inbound to local non forwarding fromnis mimics an async response coming into fromnis

	#TRUST="--proxy-cacert $ROOT/opentest.pem"
	TRUST="--cacert $ROOT/opentest.pem"

	CERTSET="--cert $ROOT/$SUBJECT.cer --key $ROOT/$SUBJECT.key --pass password"

	# subverted by hosts to localhost
	#DEST="https://$SUBJECT:4432"

	# centos-jump Opentest
	DEST="https://spineproxy.opentest.hscic.gov.uk"
	;;

	lfc)
	# clear local outbound forwarding tonis forwarding to clear gpconnect service
	PROXY="-x http://$SUBJECT:4300"
	#local  listener for tonis clear forwarder test - will return a 404 requires cfg send tls flag set to n
	DEST=http://127.0.0.1:4854/$CP # me as gpconnect

	# to gpc behind nginx - does not work! because curl strips port number 80 if http when in proxy mode and the proxy then replaces it with the spine proxy default clear port 4300!
	#DEST=http://127.0.0.1/$CP # me as gpconnect
	;;

	lfs)
	# clear local outbound forwarding tonis forwarding to secure gpconnect service requires cfg send tls flag set to y

 	# this fails because curl sends CONNECT not POST which is not what the proxy is expecting
	#PROXY="-x http://$SUBJECT:4301"

	#local  listener for tonis secure forwarder test - should return a 404
	# this also fails because curl is including a leading / in the context path
	DEST=http://127.0.0.1:4301/https://127.0.0.1:4433/$CP # me as secure gpconnect on port 443 via nginx

	#netcat -q 5 -w 5 -N 127.0.0.1 4301 < message.txt
	#exit
	;;

	rf)
	# int clear forwarding tonis on baldricks targeted at INT spine 2
	PROXY="-x http://baldricks:4300"
	# int
	DEST=https://10.239.14.26/reliablemessaging/queryrequest # spine 2 INT
	;;

	*)
	echo usage: $0' ln|lf|rf'
	exit
	;;
esac

curl $OPTIONS $PROXY $TRUST $CERTSET $PAYLOAD -H "soapaction: $SOAPACTION" $DEST | xmllint --format -

#openssl s_client -connect 192.168.1.112:4432 -tls1_1
