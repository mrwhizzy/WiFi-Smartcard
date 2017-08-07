#!/bin/sh
while true
do
	if [ ! `pgrep pcscd` ] ; then
		/usr/sbin/pcscd
		if [ ! `pgrep pcscd` ] ; then
			echo "Make sure you run this script with root privileges"
			exit
		fi
	fi
	if [ ! `pgrep vicc` ] ; then
		/usr/local/bin/vicc --esp32 &
	fi
	sleep 2
done