module_begin
module_name mem_ce
module_description check memory corrective erro
module_initdelay 0
module_interval 1
module_exec check_mem ce
module_alert    1
module_warning  1
module_warning_gen  10
module_alert_rec    3
module_warning_type    statistics
module_warning_window  30        
module_end