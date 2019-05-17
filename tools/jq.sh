#/bin/sh
if [ $# -gt 1 ];then
	exec 0<$2
fi

tag_name=`echo $1 | sed -n "s/^\.\(.*\)/\1/p"`

while read line
do
	subline=${line#*"\"${tag_name}\":\""}
	echo ${subline%%"\""*}
done<&0;

exec 0>-;


