/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include "stormfs_curl.h"

struct stormfs_curl {
  const char *url;
} stormfs_curl;

struct stormfs_curl_memory {
  char   *memory;
  size_t size;
};

static int
stormfs_curl_set_defaults(CURL *c)
{
  curl_easy_setopt(c, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(c, CURLOPT_USERAGENT, "stormfs");

  return 0;
}

static char *
stormfs_curl_get_url(const char *path)
{
  char *url;
  char tmp[strlen(stormfs_curl.url) + strlen(path) + 1];

  strcpy(tmp, stormfs_curl.url);
  strncat(tmp, path, strlen(path) + 1);
  url = strdup(tmp);

  return(url);
}

static size_t
stormfs_curl_write_memory_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
  size_t realsize = size * nmemb;
  struct stormfs_curl_memory *mem = (struct stormfs_curl_memory *) data;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    fprintf(stderr, "stormfs: memory allocation failed\n");
    abort();
  }

  memcpy(&(mem->memory[mem->size]), ptr, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

int
stormfs_curl_init(const char *url)
{
  CURLcode result;
  stormfs_curl.url = url;

  if((result = curl_global_init(CURL_GLOBAL_ALL)) != CURLE_OK)
    return -1;

  return 0;
}

int
stormfs_curl_get(const char *path)
{
  CURL *c;
  char *url = stormfs_curl_get_url(path);
  struct stormfs_curl_memory data;
  data.memory = malloc(1);
  data.size = 0;

  c = curl_easy_init();
  stormfs_curl_set_defaults(&c);
  curl_easy_setopt(c, CURLOPT_URL, url);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, stormfs_curl_write_memory_cb);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *) &data);

  curl_easy_perform(c);

  // printf("DATA:\n%s\n", data.memory);

  if(data.memory)
    free(data.memory);

  free(url);
  curl_easy_cleanup(c);

  return 0;
}

void
stormfs_curl_destroy()
{
  curl_global_cleanup();
}
