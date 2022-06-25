#include "log.h"
#include <sys/syslog.h>
#include <assert.h>
#include <unistd.h>

static int log_max_level = LOG_INFO;

int log_get_max_level(void) {
	return log_max_level;
}

void log_set_max_level(int level) {
	assert(level == (LOG_EMERG - 1) || (level & LOG_PRIMASK) == level);

	log_max_level = level;
}
