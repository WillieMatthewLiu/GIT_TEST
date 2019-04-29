/*********************************************************
* 文件名称:gap_traffic_est.c
*
* 文件功能:流量统计预估器模块(用于会话流量统计)
*
* 文件作者:zhangzq
*
* 创建日期:2017-05-19
*
* 修改历史:
	  作者:zhangzq
	  原因:新创建
	  日期:2017-05-19

 *********************************************************/
#include "command.h"
#include "gap_traffic_est.h"

#define CALC_MAX(org,now) org =(((org)>(now))?(org):(now))

 /*******************************************
 *函数名称:traffic_estimator_handle
 *函数功能:预估器的处理函数，完成流量速率计算
 *输入参数:
 *输出参数:
 *返 回 值:0是成功  ，-1是失败
 *修改历史:
	   作者:zhangzq
	   原因:新创建
	   日期:2017-05-19
  ******************************************/
int traffic_estimator_handle(struct traffic_statistics *ts, int interval)
{
	struct traffic_counters *stats = &ts->stats;
	struct traffic_estimator *est = &ts->est;

	/*计算速率*/
	est->inbps = (stats->inbytes - est->last_inbytes) / interval;
	est->outbps = (stats->outbytes - est->last_outbytes) / interval;
	est->inpps = (stats->inpkts - est->last_inpkts) / interval;
	est->outpps = (stats->outpkts - est->last_outpkts) / interval;

	/*保存旧数据*/
	est->last_inbytes = stats->inbytes;
	est->last_outbytes = stats->outbytes;
	est->last_inpkts = stats->inpkts;
	est->last_outpkts = stats->outpkts;

	/*计算速率峰值*/
	CALC_MAX(est->max_inbps, est->inbps);
	CALC_MAX(est->max_outbps, est->outbps);
	CALC_MAX(est->max_inpps, est->inpps);
	CALC_MAX(est->max_outpps, est->outpps);
	return 0;
}

