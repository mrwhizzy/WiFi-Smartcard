#!/bin/sh
while true
do
	if [ ! `pgrep pcscd` ] ; then
		/usr/sbin/pcscd
		if [ ! `pgrep pcscd` ] ; then
			echo "Make sure you are running this script as root"
			exit
		fi
	fi
	if [ ! `pgrep vicc` ] ; then
		/usr/local/bin/vicc --esp32
	fi
	sleep 2
done
