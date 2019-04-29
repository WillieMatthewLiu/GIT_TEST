#ifndef _LED_CTL_H_
#define _LED_CTL_H_

#define LED_CTL_PATH "/sys/class/rongan/fpga/led_run"
// 0: off, 1: red, 2: green, 3: red blink, 4: green blink
enum LED_TYPE
{
	LED_OFF = 0,
	LED_RED = 1,
	LED_GREEN = 2,
	LED_RED_BLINK = 3,
	LED_GREEN_BLINK = 4
};

static inline int led_ctrl(enum LED_TYPE type)
{
	char cmd[1024];
	sprintf(cmd, "echo %d > %s", type, LED_CTL_PATH);
	return system(cmd);
}

#endif
