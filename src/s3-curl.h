/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef s3_curl_H
#define s3_curl_H

void s3_curl_destroy(void);
int  s3_curl_init(struct stormfs *stormfs);

#endif // s3_curl_H
