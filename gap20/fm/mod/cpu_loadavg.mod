module_begin
module_name Load Average
module_description Average process in CPU (Last 5 minute)
module_type generic_data
module_exec cat /proc/loadavg | cut -d' ' -f2
module_alert         1
module_initdelay 0
module_interval 300
module_warning 2.8
module_critical 3.6
module_warning_gen 1
module_alert_rec 1
module_end