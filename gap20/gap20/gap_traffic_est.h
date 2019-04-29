#ifndef _GAP_TRAFFIC_EST_H_
#define _GAP_TRAFFIC_EST_H_

#define INCREASE_INPKTS(ts, v) ts.stats.inpkts += v
#define INCREASE_OUTPKTS(ts, v) ts.stats.outpkts += v
#define INCREASE_INBYTES(ts, v) ts.stats.inbytes += v
#define INCREASE_OUTBYTES(ts, v) ts.stats.outbytes += v

struct traffic_counters {
	unsigned long		inpkts;		/* incoming packets */
	unsigned long		outpkts;	/* outgoing packets */
	unsigned long		inbytes;	/* incoming bytes */
	unsigned long		outbytes;	/* outgoing bytes */
};

struct traffic_estimator {
	unsigned long last_inbytes;
	unsigned long last_outbytes;
	unsigned long last_inpkts;
	unsigned long last_outpkts;

	unsigned long  max_inbps;
	unsigned long  max_outbps;
	unsigned long  max_inpps;
	unsigned long  max_outpps;

	unsigned long  inbps;
	unsigned long  outbps;
	unsigned long  inpps;
	unsigned long  outpps;
};

struct traffic_statistics {
	struct traffic_counters stats;
	struct traffic_estimator est;
};
int traffic_estimator_handle(struct traffic_statistics *ts, int interval);

#endif

