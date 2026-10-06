#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>

#include "seccomp.h"

#define MAX_BPF_SIZE 32*1024

//This functions's name can be clearer to show what it actually does. "die" may be too ambiguous
//It would be better to change this function's name to be similar to the other functions that explicitly say what they do
//Example: print_error_then_end
void die(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

FILE* sc_must_read_and_validate_header_from_file(const char *profile_path, struct sc_seccomp_file_header *hdr)
{
	//In this function, please add the necesssary validations for the fields of the hdr struct.
	//The function's name suggests header validation, but the implementation is incompleted. Checks against supported and invalid values should be added
	FILE *file = fopen(profile_path, "rb");
	if (file == NULL) {
		die("cannot open seccomp filter %s", profile_path);
	}
	size_t num_read = fread(hdr, 1, sizeof(struct sc_seccomp_file_header), file);
	if (ferror(file) != 0) {
		die("cannot read seccomp profile %s", profile_path);
	}
	if (num_read < sizeof(struct sc_seccomp_file_header)) {
		die("short read on seccomp header: %zu", num_read);
	}
	return file;
}

void sc_must_read_filter_from_file(FILE *file, uint32_t len_bytes, struct sock_fprog *prog)
{
	//It would be better to add validation to the value of len_bytes within this function.
	//Please check for len_bytes values that are not multiples of sizeof(struct sock_filter) and we should ensure that len_bytes is less that MAX_BPF_SIZE
	//We could also check for a len_bytes value of 0 if this is not expected
	prog->len = len_bytes / sizeof(struct sock_filter);
	prog->filter = (struct sock_filter *)malloc(MAX_BPF_SIZE);
	if (prog->filter == NULL) {
		die("cannot allocate %u bytes of memory for seccomp filter ", len_bytes);
	}
	size_t num_read = fread(prog->filter, 1, len_bytes, file);
	if (ferror(file)) {
		die("cannot read filter");
	}
	if (num_read != len_bytes) {
		die("short read for filter %zu != %i", num_read, len_bytes);
	}
}

int seccomp(unsigned int operation, unsigned int flags, void *args) {
	errno = 0;
	return syscall(__NR_seccomp, operation, flags, args);
}

void sc_apply_seccomp_filter(struct sock_fprog *prog) {
	int err = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, prog);
	if (err != 0) {
		die("cannot apply seccomp profile");
	}
}

