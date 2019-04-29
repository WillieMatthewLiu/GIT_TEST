module_begin
module_name cpu temp check
module_description check cpu's temerature
module_type generic_data
module_exec dtt | grep temp2 | grep cur |awk '{print $4}'
module_alert         1
module_initdelay 0
module_interval 60
module_warning   90
module_critical  105
module_warning_gen 1
module_alert_rec   2
module_critical_exec reboot 
module_end