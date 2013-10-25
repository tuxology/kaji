#pragma once

#include <stdio.h>
#include <string.h>
#include <errno.h>

#define ERRMSG(fmt, args...)	\
	do {	\
		fprintf(stderr, fmt " (in %s() at %s:%d)\n",	\
				## args,	\
				__func__,	\
				__FILE__,	\
				__LINE__);	\
	} while (0)	\

#define ERR(fmt, args...)	ERRMSG("Error: " fmt, ## args)
#define PERROR(fmt, args...)	ERR(fmt " -> %s", ## args, strerror(errno))
#define DBG(fmt, args...)	ERRMSG("Debug: " fmt, ## args)
