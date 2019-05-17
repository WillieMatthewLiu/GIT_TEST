#ifndef __MPM_LED_H__
#define __MPM_LED_H__


#define MPM_LED_OFF 0
#define MPM_LED_RED_ON 1
#define MPM_LED_GREEN_ON 2
#define MPM_LED_RED_BLINK 3
#define MPM_LED_GREEN_BLINK 4


int mpm_set_run_led(int sw);  //sw-> LED_OFF...LED_GREEN_BLINK
int mpm_set_alarm_led(int sw);  //sw-> LED_OFF...LED_GREEN_BLINK









#endif /*__MPM_LED_H__*/
