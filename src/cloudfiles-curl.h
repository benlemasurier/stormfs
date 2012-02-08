/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef cloudfiles_curl_H
#define cloudfiles_curl_H

int cloudfiles_curl_init(struct stormfs *stormfs);
int cloudfiles_curl_head(const char *path, GList **headers);
int cloudfiles_curl_list_objects(const char *path, char **data);

#endif // cloudfiles_curl_H
