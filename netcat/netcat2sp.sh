#!/bin/bash
#
# use netcat to send a fully formed post MessageOriginator SDS adornment http request to a spine proxy
# content-length must be correct!
#

PROXY=baldricks
#PROXY=whernside
#PROXY=centos-jump

INT=QUPA_IN000005UK03
INT=QUPA_IN000006UK02

nc $PROXY 4300 < $INT.$PROXY.txt
