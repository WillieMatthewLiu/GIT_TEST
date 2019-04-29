module_begin
module_name board temp check
module_description check board's temerature
module_type generic_data
module_exec dtt | grep temp1 | grep cur |awk '{print $4}'
module_alert    1
module_initdelay 0
module_interval 60
module_warning   85
module_critical  95
module_warning_gen 1
module_alert_rec   2
module_critical_exec reboot 
module_end