#! /bin/sh
set -e

# source function library
. /etc/init.d/functions

# /etc/init.d/mpm: start and stop the mpm daemon

test -x /usr/bin/mpm || exit 0

export PATH="${PATH:+$PATH:}/usr/sbin:/sbin:/usr/bin:"

mkdir -p /data/log
case "$1" in
  start)
	echo "Starting : mpm"
	/usr/bin/mpm -d
        echo "done."
	;;
  stop)
        echo "Stopping mpm"
	pidof fm && kill -9 `pidof fm` && echo "Stopping fm"
	pidof mpm && kill -9 `pidof mpm` && echo "Stopping mpm"
	pidof gap20 && kill -9 `pidof gap20` && echo "Stopping gap20"
	pidof gap_upgrade && kill -9 `pidof gap_upgrade` && echo "Stopping gap_upgrade"
	pidof ha && kill -9 `pidof ha` && echo "Stopping ha"
	pidof db && kill -9 `pidof db` && echo "Stopping db"
	pidof zebra && kill -9 `pidof zebra` && echo "Stopping zebra"
        echo "."
	;;

  restart)
        echo "Restarting mpm"
	$0 stop
	$0 start
	;;

  *)
	echo "Usage: /etc/init.d/mpm {start|stop|restart}"
	exit 1
esac

exit 0
