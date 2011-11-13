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
#include <glib.h>
#include "stormfs_curl.h"
#include "stormfs_util.h"

#define SHA1_BLOCK_SIZE 64
#define SHA1_LENGTH 20

struct stormfs_curl {
  const char *url;
  const char *bucket;
  const char *access_key;
  const char *secret_key;
} stormfs_curl;

struct stormfs_curl_memory {
  char   *memory;
  size_t size;
};

static char *
hmac_sha1(const char *key, const char *message)
{
  unsigned int i;
  GChecksum *checksum;
  char *real_key;
  guchar ipad[SHA1_BLOCK_SIZE];
  guchar opad[SHA1_BLOCK_SIZE];
  guchar inner[SHA1_LENGTH];
  guchar digest[SHA1_LENGTH];
  gsize key_length, inner_length, digest_length;

  g_return_val_if_fail(key, NULL);
  g_return_val_if_fail(message, NULL);

  checksum = g_checksum_new(G_CHECKSUM_SHA1);

  /* If the key is longer than the block size, hash it first */
  if(strlen(key) > SHA1_BLOCK_SIZE) {
    guchar new_key[SHA1_LENGTH];

    key_length = sizeof(new_key);

    g_checksum_update(checksum, (guchar*)key, strlen(key));
    g_checksum_get_digest(checksum, new_key, &key_length);
    g_checksum_reset(checksum);

    real_key = g_memdup(new_key, key_length);
  } else {
    real_key = g_strdup(key);
    key_length = strlen(key);
  }

  /* Sanity check the length */
  g_assert(key_length <= SHA1_BLOCK_SIZE);

  /* Protect against use of the provided key by NULLing it */
  key = NULL;

  /* Stage 1 */
  memset(ipad, 0, sizeof(ipad));
  memset(opad, 0, sizeof(opad));

  memcpy(ipad, real_key, key_length);
  memcpy(opad, real_key, key_length);

  /* Stage 2 and 5 */
  for(i = 0; i < sizeof(ipad); i++) {
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5C;
  }

  /* Stage 3 and 4 */
  g_checksum_update(checksum, ipad, sizeof(ipad));
  g_checksum_update(checksum, (guchar*) message, strlen(message));
  inner_length = sizeof(inner);
  g_checksum_get_digest(checksum, inner, &inner_length);
  g_checksum_reset(checksum);

  /* Stage 6 and 7 */
  g_checksum_update(checksum, opad, sizeof(opad));
  g_checksum_update(checksum, inner, inner_length);

  digest_length = sizeof(digest);
  g_checksum_get_digest(checksum, digest, &digest_length);

  g_checksum_free(checksum);
  g_free(real_key);

  return g_base64_encode(digest, digest_length);
}

static char *
rfc2822_timestamp()
{
  char s[40];
  char *date;

  time_t t = time(NULL);
  strftime(s, sizeof(s), "%a, %d %b %Y %T %z", gmtime(&t));

  date = strdup(s);

  return date;
}

static char *
get_resource(const char *path)
{
  int path_len;
  int bucket_len;
  char *resource;

  path_len   = strlen(path);
  bucket_len = strlen(stormfs_curl.bucket);
  char tmp[1 + path_len + bucket_len + 1];

  strcpy(tmp, "/");
  strncat(tmp, stormfs_curl.bucket, bucket_len);
  strncat(tmp, path, path_len);
  resource = strdup(tmp);

  return resource;
}

static int
sign_request(const char *method, 
                          struct curl_slist **headers, const char *path)
{
  char *signature;
  GString *to_sign;
  GString *date_header;
  GString *authorization;
  struct curl_slist *next;
  struct curl_slist *header;
  char *date = rfc2822_timestamp();
  char *resource = get_resource(path);

  to_sign = g_string_new("");
  to_sign = g_string_append(to_sign, method);
  to_sign = g_string_append(to_sign, "\n\n\n");
  to_sign = g_string_append(to_sign, date);
  to_sign = g_string_append_c(to_sign, '\n');

  header = *headers;
  if(header != NULL) {
    do {
      next = header->next;
      to_sign = g_string_append(to_sign, header->data);
      to_sign = g_string_append_c(to_sign, '\n');
      header = next;
    } while(next);
  }

  to_sign = g_string_append(to_sign, resource);

  signature = hmac_sha1(stormfs_curl.secret_key, to_sign->str);

  authorization = g_string_new("Authorization: AWS ");
  authorization = g_string_append(authorization, stormfs_curl.access_key);
  authorization = g_string_append(authorization, ":");
  authorization = g_string_append(authorization, signature);

  date_header = g_string_new("Date: ");
  date_header = g_string_append(date_header, date);
  *headers = curl_slist_append(*headers, date_header->str);
  *headers = curl_slist_append(*headers, authorization->str);

  free(date);
  free(resource);
  g_string_free(to_sign, FALSE);
  g_string_free(date_header, FALSE);
  g_string_free(authorization, FALSE);

  return 0;
}

static int
set_curl_defaults(CURL **c)
{
  curl_easy_setopt(*c, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(*c, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(*c, CURLOPT_USERAGENT, "stormfs");

  return 0;
}

static char *
get_url(const char *path)
{
  char *url;
  char tmp[strlen(stormfs_curl.url) + strlen(path) + 1];

  strcpy(tmp, stormfs_curl.url);
  strncat(tmp, path, strlen(path) + 1);
  url = strdup(tmp);

  return(url);
}

static size_t
write_memory_cb(void *ptr, size_t size, size_t nmemb, void *data)
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

static int
extract_meta(char *headers, GList **meta)
{
  char *p;
  char *to_extract[8] = {
    "Content-Type",
    "Content-Length",
    "Last-Modified",
    "ETag",
    "x-amz-meta-gid",
    "x-amz-meta-uid",
    "x-amz-meta-mode",
    "x-amz-meta-mtime"
  };

  p = strtok(headers, "\n");
  while(p != NULL) {
    int i;

    for(i = 0; i < 8; i++) {
      struct http_header *h;
      char *key = to_extract[i];

      if(!strstr(p, key))
        continue;

      h = (struct http_header *) g_malloc(sizeof(struct http_header));

      h->key   = strdup(key);
      h->value = strdup(ltrim(strstr(p, " ")));

      *meta = g_list_append(*meta, h);
      break;
    }

    p = strtok(NULL, "\n");
  }

  return 0;
}

static CURL *
get_curl_handle(const char *url)
{
  CURL *c;
  c = curl_easy_init();
  set_curl_defaults(&c);
  curl_easy_setopt(c, CURLOPT_URL, url);

  return c;
}

static int
destroy_curl_handle(CURL *c)
{
  curl_easy_cleanup(c);

  return 0;
}

int
stormfs_curl_init(const char *bucket, const char *url)
{
  CURLcode result;
  stormfs_curl.url = url;
  stormfs_curl.bucket = bucket;

  if((result = curl_global_init(CURL_GLOBAL_ALL)) != CURLE_OK)
    return -1;

  return 0;
}

int
stormfs_curl_set_auth(const char *access_key, const char *secret_key)
{
  stormfs_curl.access_key = access_key;
  stormfs_curl.secret_key = secret_key;

  return 0;
}

int
stormfs_curl_get(const char *path)
{
  char *url = get_url(path);
  CURL *c = get_curl_handle(url);
  struct curl_slist *req_headers = NULL; 
  struct stormfs_curl_memory data;

  data.memory = g_malloc(1);
  data.size = 0;

  sign_request("GET", &req_headers, path);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *) &data);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_memory_cb);

  curl_easy_perform(c);

  // FIXME: (testing)
  printf("HTTP BODY:\n%s\n", data.memory);

  if(data.memory)
    g_free(data.memory);

  g_free(url);
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return 0;
}

int
stormfs_curl_head(const char *path, GList **meta)
{
  char *url = get_url(path);
  char *response_headers;
  CURL *c = get_curl_handle(url);
  struct curl_slist *req_headers = NULL;
  struct stormfs_curl_memory data;

  data.memory = g_malloc(1);
  data.size = 0;

  sign_request("HEAD", &req_headers, path);
  curl_easy_setopt(c, CURLOPT_NOBODY, 1L);    // HEAD
  curl_easy_setopt(c, CURLOPT_FILETIME, 1L);  // Last-Modified
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, (void *) &data);
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, write_memory_cb);

  curl_easy_perform(c);

  response_headers = strdup(data.memory);
  extract_meta(response_headers, &(*meta));

  // FIXME: (testing)
  printf("HTTP HEADER:\n%s\n", data.memory);

  if(data.memory)
    g_free(data.memory);

  g_free(url);
  g_free(response_headers);
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return 0;
}

void
stormfs_curl_destroy()
{
  curl_global_cleanup();
}
