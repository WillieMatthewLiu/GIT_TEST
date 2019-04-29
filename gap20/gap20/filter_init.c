int filter_init()
{
	parser_db2_pktfilter_reg();
	parser_ftp_pktfilter_reg();
	parser_ftpdata_pktfilter_reg();
	parser_http_pktfilter_reg();
	parser_https_pktfilter_reg();
	parser_iec104_pktfilter_reg();
	parser_kernel_pktfilter_reg();
	parser_mail_pktfilter_reg();
	parser_modbus_pktfilter_reg();
	parser_mssql_pktfilter_reg();
	parser_mysql_pktfilter_reg();
	parser_netbios_pktfilter_reg();
	parser_opc_pktfilter_reg();
	parser_opc_data_pktfilter_reg();
	parser_opc_ssdp_pktfilter_reg();
	parser_orcl_pktfilter_reg();
	parser_pop3_pktfilter_reg();
	parser_rtsp_pktfilter_reg();
	parser_rtsp_data_pktfilter_reg();
	parser_sip_pktfilter_reg();
	parser_sip_data_pktfilter_reg();
	parser_smtp_pktfilter_reg();
	parser_ssh_pktfilter_reg();
	parser_ssl_pktfilter_reg();
	parser_tcp_pktfilter_reg();
	parser_tdcs_pktfilter_reg();
	parser_udp_pktfilter_reg();

	return pktfilter_init();
}

int filter_free()
{
	pktfilter_exit();
	parser_db2_pktfilter_unreg();
	parser_ftp_pktfilter_unreg();
	parser_ftpdata_pktfilter_unreg();
	parser_http_pktfilter_unreg();
	parser_https_pktfilter_unreg();
	parser_iec104_pktfilter_unreg();
	parser_kernel_pktfilter_unreg();
	parser_mail_pktfilter_unreg();
	parser_modbus_pktfilter_unreg();
	parser_mssql_pktfilter_unreg();
	parser_mysql_pktfilter_unreg();
	parser_netbios_pktfilter_unreg();
	parser_opc_pktfilter_unreg();
	parser_opc_data_pktfilter_unreg();
	parser_opc_ssdp_pktfilter_unreg();
	parser_orcl_pktfilter_unreg();
	parser_pop3_pktfilter_unreg();
	parser_rtsp_pktfilter_unreg();
	parser_rtsp_data_pktfilter_unreg();
	parser_sip_pktfilter_unreg();
	parser_sip_data_pktfilter_unreg();
	parser_smtp_pktfilter_unreg();
	parser_ssh_pktfilter_unreg();
	parser_ssl_pktfilter_unreg();
	parser_tcp_pktfilter_unreg();
	parser_tdcs_pktfilter_unreg();
	parser_udp_pktfilter_unreg();
}