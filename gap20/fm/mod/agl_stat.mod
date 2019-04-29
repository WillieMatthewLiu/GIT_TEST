module_begin                                                                     
module_name check agl0 stat
module_type generic_data
module_exec check_network agl0
module_interval 1
module_description check agl0 phy status
module_initdelay     0
module_alert         1
module_warning       1
module_warning_gen   1
module_alert_rec     1
module_condition     =
module_end


