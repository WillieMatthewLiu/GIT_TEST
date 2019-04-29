#ifndef _SIGNALS_H
#define _SIGNALS_H

 /* Prototypes */
 /* Currently unused extern int signal_pending(void); */
extern void *signal_set(int signo, void(*func) (void *, int), void *);
extern void *signal_ignore(int signo);

extern void signal_handler_init(void);
extern void signal_handler_destroy(void);
extern void signal_handler_reset(void);
extern void signal_handler_script(void);
extern void signal_run_callback(void);

extern int signal_rfd(void);
extern void signal_pipe_close(int);

#endif
