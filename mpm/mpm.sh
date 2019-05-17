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
	pidof mpm && kill -9 `pidof mpm` && echo "Stopping mpm"
	pidof app.out && kill -9 `pidof app.out` && echo "Stopping app.out"
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
