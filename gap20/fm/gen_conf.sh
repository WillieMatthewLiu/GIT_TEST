#! /bin/sh
conf_path="/etc/fm"
base_conf="base_agent.conf"
mod_files=`ls ${conf_path}/mod/*.mod`
all_conf="fm_agent.conf"
cd $conf_path
if [ -f /var/run/boardtype ];then
	mode=`cat /var/run/boardtype`
	if [ "$mode" != "" ];then
		sed -i "s/agent_name Arbiter/agent_name $mode/g" $base_conf
	fi
fi
cat $base_conf > $all_conf
echo -e "\n" >> $all_conf

for file in $mod_files
do
	valid=`cat $file | grep module_begin`
	if [ "$valid" != "" ];then
		echo -e "`cat $file`\n" >> $all_conf
	fi
done
