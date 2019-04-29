module_begin
module_name mem usage
module_description check used memory usage
module_initdelay 0
module_interval 10
module_exec check_usage mem
module_alert         1
module_warning  80
module_critical 90
module_warning_gen  1
module_alert_rec    5
module_end