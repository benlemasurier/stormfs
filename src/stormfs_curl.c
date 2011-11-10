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
#include <time.h>
#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <gcrypt.h>
#include <glib.h>
#include "stormfs_curl.h"

struct stormfs_curl {
  const char *url;
} stormfs_curl;

struct stormfs_curl_memory {
  char   *memory;
  size_t size;
};

static int
stormfs_curl_sign_request(struct curl_slist *headers, const char *path)
{
  // TODO:
  char *to_sign = "TEST"; 
  const char *key = "TEST";

  int mdlen;
  size_t n_bytes;
  gcry_error_t error = 0;
  gcry_md_hd_t digest = NULL;
  unsigned char *md_string = NULL;

  error = gcry_md_open(&digest, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
  if(error) {
    fprintf(stderr, "stormfs: %s\n", gcry_strerror(error));
    abort();
  }

  mdlen = gcry_md_get_algo_dlen(GCRY_MD_SHA1);

  error = gcry_md_setkey(digest, key, strlen(key));
  if(error) {
    fprintf(stderr, "stormfs: %s\n", gcry_strerror(error));
    abort();
  }

  gcry_md_write(digest, to_sign, strlen(to_sign));
  md_string = gcry_md_read(digest, 0);

  int i;
  for(i = 0; i < mdlen; i++)
    printf("%02x ", md_string[i] & 0xFF);
  printf("\n");

  gcry_md_close(digest);

  printf("SIGNATURE: %s\n", md_string);

  return 0;
}

static const char *
stormfs_curl_rfc2822_timestamp()
{
  char s[40];
  char *date;

  time_t t = time(NULL);
  strftime(s, sizeof(s), "Date: %a, %d %b %Y %T %z", gmtime(&t));

  date = strdup(s);

  return date;
}

static int
stormfs_curl_set_defaults(CURL *c)
{
  // FIXME: why not work?
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

  mem->memory = g_realloc(mem->memory, mem->size + realsize + 1);
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

  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);

  return 0;
}

int
stormfs_curl_get(const char *path)
{
  CURL *c;
  char *url = stormfs_curl_get_url(path);
  struct curl_slist *headers = NULL; 
  struct stormfs_curl_memory data;
  data.memory = g_malloc(1);
  data.size = 0;

  headers = curl_slist_append(headers, stormfs_curl_rfc2822_timestamp());
  stormfs_curl_sign_request(headers, path);

  c = curl_easy_init();
  stormfs_curl_set_defaults(&c);
  curl_easy_setopt(c, CURLOPT_URL, url);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, stormfs_curl_write_memory_cb);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *) &data);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(c, CURLOPT_VERBOSE, 1L);

  curl_easy_perform(c);

  printf("DATA:\n%s\n", data.memory);

  if(data.memory)
    g_free(data.memory);

  g_free(url);
  curl_easy_cleanup(c);
  curl_slist_free_all(headers);

  return 0;
}

void
stormfs_curl_destroy()
{
  curl_global_cleanup();
}
