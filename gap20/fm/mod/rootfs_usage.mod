module_begin
module_name rootfs usage
module_description check rootfs partition usage
module_initdelay 0
module_interval 30
module_exec check_usage rootfs
module_alert    1
module_warning  80
module_critical 90
module_warning_gen  1
module_alert_rec    1
module_end