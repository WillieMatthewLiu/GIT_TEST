module_begin
module_name mem_ue
module_description check memory uncorrective err
module_initdelay 0
module_interval 2
module_exec check_mem ue
module_alert    1
module_critical 1
module_critical_exec reboot
module_warning_gen  1
module_alert_rec    3
module_end