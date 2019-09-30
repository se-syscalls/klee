#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <klee/klee.h>

int setrlimit(int resource, const struct rlimit *rlim) {
	errno = klee_int(__FUNCTION__);
	return klee_range(-1, 1, __FUNCTION__);
}
