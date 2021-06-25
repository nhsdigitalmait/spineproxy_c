#!/bin/bash
#
# use netcat to send a fully formed post MessageOriginator SDS adornment http request to a spine proxy
# content-length must be correct!
#

PROXY1=baldricks
#PROXY=whernside
PROXY=centos-jump

nc $PROXY 4300 < QUPA_IN000005UK03.$PROXY.txt
