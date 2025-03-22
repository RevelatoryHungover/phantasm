#include <syslog.h>
#include <unistd.h>
__attribute__((constructor))
int logger(int fd){
    openlog("PHANTASM_SO", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "PHANTASM LOADED PID: %d, mem: %llx",getpid(),(void*)logger);
    closelog();
}
