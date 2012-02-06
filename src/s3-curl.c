/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#define _GNU_SOURCE

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include "stormfs.h"
#include "curl.h"

struct s3_curl {
  struct stormfs *stormfs;
} s3_curl;

int
s3_curl_init(struct stormfs *stormfs)
{
  s3_curl.stormfs = stormfs;

  return stormfs_curl_init(stormfs);
}

void
s3_curl_destroy(void)
{
  stormfs_curl_destroy();
}
