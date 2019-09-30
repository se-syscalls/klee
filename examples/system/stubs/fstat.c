#include <alloca.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <klee/klee.h>

#include "stubs_helper_macros.h"

int fstat(int fd, struct stat *buf) {
	HAVOC(buf);
	errno = klee_int(__FUNCTION__);
	return klee_range(-1, 1, __FUNCTION__);
}
