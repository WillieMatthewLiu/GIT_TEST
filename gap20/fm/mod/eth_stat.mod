module_begin                                                                     
module_name check eth stat
module_type generic_data
module_exec check_network eth
module_interval 1
module_description check eth's phy status
module_initdelay     0
module_alert         1
module_warning       1
module_warning_gen   1
module_alert_rec     1
module_condition     =
module_end


