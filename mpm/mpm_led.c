#ifdef __cplusplus
extern "C"{
#endif
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>



#include "mpm_led.h"
#ifdef ACORN7020_KED

static const char *run_led_dev = "/sys/class/acorn/cpld/led_run";
static const char *alarm_led_dev = "/sys/class/acorn/cpld/led_alarm";

static void mpm_set_sw_led_buf(char buf[],int sw)
{
    switch (sw) {
    case MPM_LED_OFF:
        buf[0] = '0';
        break;
    case MPM_LED_RED_ON:
        buf[0] = '1';
        break;
    case MPM_LED_GREEN_ON:
        buf[0] = '2';
        break;
    case MPM_LED_RED_BLINK:
        buf[0] = '3';
        break;
    case MPM_LED_GREEN_BLINK:
        buf[0] = '4';
        break;
    default:
        break;
    }
}
#endif

int mpm_set_run_led(int sw)
{
#ifndef X86_PLATFORM
#ifdef ACORN7020_KED
    int fd;
    char buf[8];

    fd = open(run_led_dev,  O_WRONLY);
    if (-1 == fd) {
        return -1;
    }
    mpm_set_sw_led_buf(buf, sw);
    if(-1 == write(fd, buf, 1))
    {
        close(fd);
        return -1;
    }
    close(fd);
#else
    char cmdbuf[128]={0};
    switch(sw){
        case MPM_LED_OFF:
            sprintf(cmdbuf, "echo %d > /sys/class/leds/green/brightness", 0);
            break;
        case MPM_LED_GREEN_ON:
            sprintf(cmdbuf, "echo %d > /sys/class/leds/green/brightness", 1);
            break;
        case MPM_LED_GREEN_BLINK:
            sprintf(cmdbuf, "echo timer > /sys/class/leds/green/trigger");
            break;
        default:
            return 0;
    }

    system(cmdbuf);
#endif
#endif /* X86_PLATFORM */
     return 0;

}


int mpm_set_alarm_led(int sw)
{
#ifndef X86_PLATFORM
#ifdef ACORN7020_KED
    int fd;
    char buf[8];

    fd = open(alarm_led_dev,  O_WRONLY);
    if (-1 == fd) {
        return -1;
    }
    mpm_set_sw_led_buf(buf, sw);
     if(-1 == write(fd, buf, 1))
     {
         close(fd);
         return -1;
     }
     close(fd);
#else
    char cmdbuf[128]={0};
    switch(sw){
        case MPM_LED_OFF:
            sprintf(cmdbuf, "echo %d > /sys/class/leds/red/brightness", 0);
            break;
        case MPM_LED_RED_ON:
            sprintf(cmdbuf, "echo %d > /sys/class/leds/red/brightness", 1);
            break;
        case MPM_LED_RED_BLINK:
            sprintf(cmdbuf, "echo timer > /sys/class/leds/red/trigger");
            break;
        default:
            return 0;
    }

    system(cmdbuf);
#endif
#endif /* X86_PLATFORM */
     return 0;
}





#ifdef __cplusplus
}
#endif
