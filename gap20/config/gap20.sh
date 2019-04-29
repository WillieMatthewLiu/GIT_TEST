#! /bin/sh
set -e

# source function library
. /etc/init.d/functions

# /etc/init.d/gap20: start and stop the gap20

test -x /usr/bin/gap20 || exit 0

export PATH="${PATH:+$PATH:}/usr/sbin:/sbin:/usr/bin:"

mkdir -p /data/log
case "$1" in
  start)
	echo "Starting : gap20"
	iptables -t nat -F
	modprobe gap-kernel
	/usr/bin/gap20 -D
        echo "done."
	;;
  stop)
        echo "Stopping gap20"
	pidof gap20 && kill -9 `pidof gap20` && echo "Stopping gap20"
	rmmod gap-kernel
        echo "."
	;;

  restart)
        echo "Restarting gap20"
	$0 stop
	$0 start
	;;

  *)
	echo "Usage: /etc/init.d/gap20 {start|stop|restart}"
	exit 1
esac

exit 0
