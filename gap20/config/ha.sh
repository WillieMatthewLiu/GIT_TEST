#! /bin/sh
set -e

# source function library
. /etc/init.d/functions

# /etc/init.d/gap20: start and stop the gap20

test -x /usr/bin/ha || exit 0

export PATH="${PATH:+$PATH:}/usr/sbin:/sbin:/usr/bin:"

mkdir -p /data/log
case "$1" in
  start)
	echo "Starting : ha"
	/usr/bin/ha -D
        echo "done."
	;;
  stop)
        echo "Stopping ha"
	pidof ha && kill -9 `pidof ha` && echo "Stopping ha"
        echo "."
	;;

  restart)
        echo "Restarting ha"
	$0 stop
	$0 start
	;;

  *)
	echo "Usage: /etc/init.d/ha {start|stop|restart}"
	exit 1
esac

exit 0
