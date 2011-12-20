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
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <pthread.h>
#include <glib.h>
#include "stormfs.h"
#include "curl.h"

#define CURL_RETRIES 3
#define SHA1_BLOCK_SIZE 64
#define SHA1_LENGTH 20
#define MAX_REQUESTS 100
#define POOL_SIZE 100
#define DEFAULT_MIME_TYPE "application/octet-stream"

static pthread_mutex_t lock        = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t shared_lock = PTHREAD_MUTEX_INITIALIZER;

struct stormfs_curl {
  int verify_ssl;
  const char *url;
  const char *bucket;
  const char *access_key;
  const char *secret_key;
  GList *pool;
  GList *marker;
  bool pool_full;
  CURLM *multi;
  CURLSH *share;
} curl;

typedef struct {
  CURL *c;
  bool in_use;
} CURL_HANDLE;

typedef struct {
  char   *memory;
  size_t size;
} HTTP_RESPONSE;

typedef struct {
  CURL *c;
  char *url;
  char *path;
  bool done;
  HTTP_RESPONSE response;
  struct curl_slist *headers;
} HTTP_REQUEST;

static char *
gid_to_s(gid_t gid)
{
  char s[100];
  snprintf(s, 100, "%lu", (unsigned long) gid);

  return strdup(s);
}

static char *
uid_to_s(uid_t uid)
{
  char s[100];
  snprintf(s, 100, "%lu", (unsigned long) uid);

  return strdup(s);
}

static char *
mode_to_s(mode_t mode)
{
  char s[100];
  snprintf(s, 100, "%lu", (unsigned long) mode);

  return strdup(s);
}

static char *
time_to_s(time_t t)
{
  char s[100];
  snprintf(s, 100, "%ld", (long) t);

  return strdup(s);
}

char
char_to_hex(char c)
{
  static char hex[] = "0123456789abcdef";

  return hex[c & 15];
}

static int
cmpstringp(const void *p1, const void *p2)
{
  return strcmp(*(char **) p1, *(char **) p2);
}

void
free_header(HTTP_HEADER *h)
{
  g_free(h->key);
  g_free(h->value);
  g_free(h);
}

void
free_headers(GList *headers)
{
  g_list_free_full(headers, (GDestroyNotify) free_header);
}

char *
url_encode(char *s)
{
  char *p = s;
  char *buf = g_malloc((strlen(s) * 3) + 1);
  char *pbuf = buf;

  // NOTE: '/' will not be url encoded
  while(*p) {
    if(isalnum(*p) || *p == '/' || *p == '-' || *p == '_' || *p == '.' || *p == '~')
      *pbuf++ = *p;
    else if(*p == ' ')
      *pbuf++ = '+';
    else
      *pbuf++ = '%', *pbuf++ = char_to_hex(*p >> 4), *pbuf++ = char_to_hex(*p & 15);

    p++;
  }

  *pbuf = '\0';
  return buf;
}
 
static char *
get_resource(const char *path)
{
  int path_len = strlen(path);
  int bucket_len = strlen(curl.bucket);
  char *resource = g_malloc0(sizeof(char) * path_len + bucket_len + 2);

  strncpy(resource, "/", 1);
  strncat(resource, curl.bucket, bucket_len);
  strncat(resource, path, path_len);

  return resource;
}

HTTP_HEADER *
acl_header(const char *acl)
{
  HTTP_HEADER *h = g_malloc(sizeof(HTTP_HEADER));

  h->key = strdup("x-amz-acl");
  h->value = strdup(acl);

  return h;
}

HTTP_HEADER *
content_header(const char *type)
{
  HTTP_HEADER *h = g_malloc(sizeof(HTTP_HEADER));

  h->key   = strdup("Content-Type");
  if(type == NULL)
    h->value = strdup(DEFAULT_MIME_TYPE);
  else
    h->value = strdup(type);

  return h;
}

HTTP_HEADER *
copy_meta_header()
{
  HTTP_HEADER *h = g_malloc(sizeof(HTTP_HEADER));

  h->key   = strdup("x-amz-metadata-directive");
  h->value = strdup("COPY");

  return h;
}

HTTP_HEADER *
copy_source_header(const char *path)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-copy-source");
  h->value = get_resource(path);

  return h;
}

HTTP_HEADER *
ctime_header(time_t t)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-meta-ctime");
  h->value = time_to_s(t);

  return h;
}

HTTP_HEADER *
expires_header(const char *expires)
{
  HTTP_HEADER *h = g_malloc(sizeof(HTTP_HEADER));

  h->key = strdup("Expires");
  h->value = strdup(expires);

  return h;
}

HTTP_HEADER *
gid_header(gid_t gid)
{
  char *s = gid_to_s(gid);
  HTTP_HEADER *h = g_malloc(sizeof(HTTP_HEADER));

  h->key   = strdup("x-amz-meta-gid");
  h->value = s;

  return h;
}

HTTP_HEADER *
mode_header(mode_t mode)
{
  char *s = mode_to_s(mode);
  HTTP_HEADER *h = g_malloc(sizeof(HTTP_HEADER));

  h->key   = strdup("x-amz-meta-mode");
  h->value = s;

  return h;
}

HTTP_HEADER *
mtime_header(time_t t)
{
  char *s = time_to_s(t);
  HTTP_HEADER *h = g_malloc(sizeof(HTTP_HEADER));

  h->key = strdup("x-amz-meta-mtime");
  h->value = s;

  return h;
}

HTTP_HEADER *
replace_header()
{
  HTTP_HEADER *h = g_malloc(sizeof(HTTP_HEADER));

  h->key   = strdup("x-amz-metadata-directive");
  h->value = strdup("REPLACE");

  return h;
}

HTTP_HEADER *
storage_header(const char *class)
{
  HTTP_HEADER *h = g_malloc(sizeof(HTTP_HEADER));

  h->key = strdup("x-amz-storage-class");
  h->value = strdup(class);

  return h;
}

HTTP_HEADER *
uid_header(uid_t uid)
{
  char *s = uid_to_s(uid);
  HTTP_HEADER *h = g_malloc(sizeof(HTTP_HEADER));

  h->key   = strdup("x-amz-meta-uid");
  h->value = s;

  return h;
}

GList *
strip_header(GList *headers, const char *key)
{
  GList *head = NULL, *next = NULL;

  head = g_list_first(headers);
  while(head != NULL) {
    next = head->next;
    HTTP_HEADER *header = head->data;

    if(strstr(header->key, key) != NULL)
      headers = g_list_remove(headers, head);

    head = next;
  }

  return headers;
}

GList *
add_header(GList *headers, HTTP_HEADER *h)
{
  headers = strip_header(headers, h->key);
  headers = g_list_append(headers, h);

  return headers;
}

static bool
is_truncated(char *xml)
{
  if(strstr(xml, "<IsTruncated>true"))
    return true;

  return false;
}

static char *
get_next_marker(char *xml)
{
  char *start_marker = "NextMarker>";
  char *end_marker  = "</NextMarker";
  char *start_p, *end_p;

  start_p = strstr(xml, start_marker) + strlen(start_marker);
  end_p   = strstr(xml, end_marker);

  return g_strndup(start_p, end_p - start_p);
}

static char *
append_list_bucket_xml(char *xml, char *xml_to_append)
{
  char *append_pos, *to_append;

  // TODO: should be able to use a little less memory here.
  xml = g_realloc(xml, sizeof(char) *
      strlen(xml) + strlen(xml_to_append) + 1);

  append_pos = strstr(xml, "</ListBucket");
  to_append  = strstr(xml_to_append, "<Contents");

  *append_pos = '\0';
  strncat(append_pos, to_append, strlen(to_append));

  return xml;
}

char *
header_to_s(HTTP_HEADER *h)
{
  char *s;
  s = g_malloc0(sizeof(char) * strlen(h->key) + strlen(h->value) + 2);
  s = strcpy(s, h->key);
  s = strcat(s, ":");
  s = strncat(s, h->value, strlen(h->value));

  return s;
}

struct curl_slist *
headers_to_curl_slist(GList *headers)
{
  GList *head = NULL, *next = NULL;
  struct curl_slist *curl_headers = NULL;

  headers = g_list_sort(headers, (GCompareFunc) cmpstringp);

  head = g_list_first(headers);
  while(head != NULL) {
    next = head->next;
    HTTP_HEADER *h = head->data;

    char *s = header_to_s(h);
    if(strstr(h->key, "x-amz-") != NULL || strstr(h->key, "Expires") != NULL)
      curl_headers = curl_slist_append(curl_headers, s);
    else if(strstr(h->key, "Content-Type") != NULL)
      curl_headers = curl_slist_append(curl_headers, s);
    g_free(s);

    head = next;
  }

  return curl_headers;
}

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

  // If the key is longer than the block size, hash it first
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

  // Sanity check the length
  g_assert(key_length <= SHA1_BLOCK_SIZE);

  // Protect against use of the provided key by NULLing it
  key = NULL;

  // Stage 1
  memset(ipad, 0, sizeof(ipad));
  memset(opad, 0, sizeof(opad));

  memcpy(ipad, real_key, key_length);
  memcpy(opad, real_key, key_length);

  // Stage 2 and 5
  for(i = 0; i < sizeof(ipad); i++) {
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5C;
  }

  // Stage 3 and 4
  g_checksum_update(checksum, ipad, sizeof(ipad));
  g_checksum_update(checksum, (guchar*) message, strlen(message));
  inner_length = sizeof(inner);
  g_checksum_get_digest(checksum, inner, &inner_length);
  g_checksum_reset(checksum);

  // Stage 6 and 7
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
  strftime(s, sizeof(s), "%a, %d %b %Y %T GMT", gmtime(&t));

  date = strdup(s);

  return date;
}

static int
http_response_errno(CURLcode response_code, CURL *handle)
{
  long http_response;

  switch(response_code) {
    case CURLE_OK:
      if(curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_response) != 0)
        return -EIO;
      if(http_response == 401)
        return -EACCES;
      if(http_response == 403)
        return -EACCES;
      if(http_response == 404)
        return -ENOENT;
      if(http_response >= 400 && http_response < 500)
        return -EIO;
      if(http_response >= 500)
        return -EAGAIN;

      return 0;

    case CURLE_COULDNT_RESOLVE_HOST:
      return -EAGAIN;
    case CURLE_COULDNT_CONNECT:
      return -EAGAIN;
    case CURLE_WRITE_ERROR:
      return -EAGAIN;
    case CURLE_UPLOAD_FAILED:
      return -EAGAIN;
    case CURLE_READ_ERROR:
      return -EAGAIN;
    case CURLE_OPERATION_TIMEDOUT:
      return -EAGAIN;
    case CURLE_SEND_ERROR:
      return -EAGAIN;
    case CURLE_RECV_ERROR:
      return -EAGAIN;
    case CURLE_AGAIN:
      return -EAGAIN;

    default:
      return -EIO;
  }

  return 0;
}

static void
share_lock(CURL *c, curl_lock_data data, curl_lock_access laccess, void *p)
{
  pthread_mutex_lock(&shared_lock);
}

static void
share_unlock(CURL *c, curl_lock_data data, void *p)
{
  pthread_mutex_unlock(&shared_lock);
}

static int
stormfs_curl_easy_perform(CURL *c)
{
  int result;
  CURLcode code;
  uint8_t attempts = 0;

  code = curl_easy_perform(c);
  while(attempts < CURL_RETRIES) {
    if((result = http_response_errno(code, c)) != -EAGAIN)
      break;

    attempts++;
    curl_easy_perform(c);
  }

  return result;
}

static int
sign_request(const char *method,
    struct curl_slist **headers, const char *path)
{
  char *signature;
  char *to_sign;
  char *date_header;
  char *amz_headers;
  char *content_type;
  char *authorization;
  struct curl_slist *next = NULL;
  struct curl_slist *header = NULL;
  char *date = rfc2822_timestamp();
  char *resource = get_resource(path);

  amz_headers  = g_malloc0(sizeof(char));
  content_type = g_malloc0(sizeof(char) * 2);
  header = *headers;
  while(header != NULL) {
    next = header->next;

    if(strstr(header->data, "x-amz") != NULL) {
      amz_headers = g_realloc(amz_headers, sizeof(char) * strlen(amz_headers) +
                        strlen(header->data) + 2);
      amz_headers = strncat(amz_headers, header->data, strlen(header->data));
      amz_headers = strncat(amz_headers, "\n", 1);
    } else if(strstr(header->data, "Content-Type") != NULL) {
      char *tmp = strstr(header->data, ":") + 1;
      content_type = g_realloc(content_type, sizeof(char) * strlen(content_type) +
                        strlen(content_type) + strlen(tmp) + 2);
      content_type = strncat(content_type, tmp, strlen(tmp));
    }

    header = next;
  }

  content_type = strncat(content_type, "\n", 1);
  to_sign = g_malloc(sizeof(char) * strlen(method) +
                strlen(content_type) + strlen(date) +
                strlen(amz_headers) + strlen(resource) + 4);
  to_sign = strcpy(to_sign, method);
  to_sign = strcat(to_sign, "\n\n");
  to_sign = strcat(to_sign, content_type);
  to_sign = strcat(to_sign, date);
  to_sign = strcat(to_sign, "\n");
  to_sign = strcat(to_sign, amz_headers);
  to_sign = strcat(to_sign, resource);

  signature = hmac_sha1(curl.secret_key, to_sign);

  authorization = g_malloc(sizeof(char) * strlen(curl.access_key) +
                                          strlen(signature) + 22);
  authorization = strcpy(authorization, "Authorization: AWS ");
  authorization = strcat(authorization, curl.access_key);
  authorization = strcat(authorization, ":");
  authorization = strcat(authorization, signature);

  date_header = g_malloc(sizeof(char) * strlen(date) + 7);
  date_header = strcpy(date_header, "Date: ");
  date_header = strcat(date_header, date);
  *headers = curl_slist_append(*headers, date_header);
  *headers = curl_slist_append(*headers, authorization);

  g_free(date);
  g_free(resource);
  g_free(signature);
  g_free(to_sign);
  g_free(amz_headers);
  g_free(date_header);
  g_free(content_type);
  g_free(authorization);

  return 0;
}

static int
set_curl_defaults(CURL *c)
{
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(c, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt(c, CURLOPT_USERAGENT, "stormfs");
  curl_easy_setopt(c, CURLOPT_DNS_CACHE_TIMEOUT, -1);
  curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, curl.verify_ssl);
  curl_easy_setopt(c, CURLOPT_SHARE, curl.share);

  // curl_easy_setopt(c, CURLOPT_TCP_NODELAY, 1);
  // curl_easy_setopt(c, CURLOPT_VERBOSE, 1L);
  // curl_easy_setopt(c, CURLOPT_FORBID_REUSE, 1);

  return 0;
}

static char *
get_url(const char *path)
{
  char *tmp = url_encode((char *) path);
  char *delimiter = "?delimiter=/";
  char *url = g_malloc(sizeof(char) *
      strlen(curl.url) +
      strlen(tmp) +
      strlen(delimiter) + 1);

  url = strcpy(url, curl.url);
  url = strncat(url, tmp, strlen(tmp));
  url = strncat(url, delimiter, strlen(delimiter));
  g_free(tmp);

  return(url);
}

static char *
get_list_bucket_url(const char *path, const char *next_marker)
{
  char *url, *tmp;
  const char *delimiter  = "?delimiter=/";
  const char *prefix     = "&prefix=";
  const char *marker     = "&marker=";
  size_t url_len         = strlen(curl.url);
  size_t delimiter_len   = strlen(delimiter);
  size_t prefix_len      = strlen(prefix);
  size_t path_len        = strlen(path);
  size_t marker_len      = strlen(marker) + strlen(next_marker);

  tmp = g_malloc(sizeof(char) * (url_len + delimiter_len +
      marker_len + prefix_len + 1));

  tmp = strcpy(tmp, curl.url);
  tmp = strncat(tmp, delimiter, delimiter_len);
  tmp = strncat(tmp, marker, strlen(marker));
  tmp = strncat(tmp, next_marker, strlen(next_marker));
  tmp = strncat(tmp, prefix, prefix_len);

  if(path_len > 1) {
    tmp = g_realloc(tmp, sizeof(char) * (strlen(tmp) + path_len + 1));
    tmp = strncat(tmp, path + 1, path_len - 1);
    tmp = strncat(tmp, "/", 1);
  }

  url = g_strdup(tmp);
  g_free(tmp);

  return(url);
}

static size_t
write_memory_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
  size_t realsize = size * nmemb;
  HTTP_RESPONSE *mem = data;

  mem->memory = g_realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    fprintf(stderr, "stormfs: memory allocation failed\n");
    exit(EXIT_FAILURE);
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

  p = strtok(headers, "\r\n");
  while(p != NULL) {
    int i;

    for(i = 0; i < 8; i++) {
      HTTP_HEADER *h;
      char *key = to_extract[i];
      char *value;

      if(!strstr(p, key))
        continue;

      h = g_malloc(sizeof(HTTP_HEADER));
      h->key = strdup(key);
      value = strstr(p, " ");
      value++; // remove leading space
      h->value = strdup(value);

      *meta = g_list_append(*meta, h);
      break;
    }

    p = strtok(NULL, "\r\n");
  }

  return 0;
}

static CURL *
get_curl_handle(const char *url)
{
  CURL *c;
  c = curl_easy_init();
  set_curl_defaults(c);
  curl_easy_setopt(c, CURLOPT_URL, url);

  return c;
}

static int
destroy_curl_handle(CURL *c)
{
  curl_easy_cleanup(c);

  return 0;
}

CURL_HANDLE *
create_pooled_handle(const char *url)
{
  CURL_HANDLE *ch = g_new0(CURL_HANDLE, 1);
  ch->c = get_curl_handle(url);
  ch->in_use = false;

  return ch;
}

static int
destroy_pooled_handle(CURL_HANDLE *ch)
{
  destroy_curl_handle(ch->c);
  g_free(ch);

  return 0;
}

static int
destroy_pool(void)
{
  g_list_free_full(curl.pool, (GDestroyNotify) destroy_pooled_handle);

  return 0;
}

static int
pool_init(void)
{
  curl.pool_full = false;
  for(uint8_t i = 0; i < POOL_SIZE; i++)
    curl.pool = g_list_append(curl.pool, create_pooled_handle(curl.url));

  return 0;
}

CURL *
get_pooled_handle(const char *url)
{
  GList *head = NULL, *next = NULL;

  pthread_mutex_lock(&lock);

  /* attempt to immediately grab the next available handle */
  if(curl.marker != NULL)
    head = curl.marker;
  else
    head = g_list_first(curl.pool);

  while(head != NULL && !curl.pool_full) {
    if(head->next != NULL)
      next = head->next;
    else
      next = g_list_first(curl.pool);

    CURL_HANDLE *ch = head->data;
    if(!ch->in_use) {
      ch->in_use = true;
      curl_easy_setopt(ch->c, CURLOPT_URL, url);
      curl.marker = next;
      pthread_mutex_unlock(&lock);
      return ch->c;
    }

    head = next;
    if(head == curl.marker) {
      curl.pool_full = true;
      break;
    }
  }

  pthread_mutex_unlock(&lock);

  // no handles available in the pool, just create a new one.
  return get_curl_handle(url);
}

void
release_pooled_handle(CURL *c)
{
  bool is_pooled_handle = false;
  GList *head = NULL, *next = NULL;

  pthread_mutex_lock(&lock);
  head = g_list_first(curl.pool);
  while(head != NULL) {
    next = head->next;
    CURL_HANDLE *ch = head->data;
    if(ch->c == c) {
      curl_easy_reset(ch->c);
      ch->in_use = false;
      curl.pool_full = false;
      is_pooled_handle = true;
      break;
    }
    head = next;
  }
  pthread_mutex_unlock(&lock);

  if(!is_pooled_handle)
    destroy_curl_handle(c);
}

HTTP_REQUEST *
new_request(const char *path)
{
  HTTP_REQUEST *request = g_new0(HTTP_REQUEST, 1);

  request->done = false;
  request->path = g_strdup(path);
  request->url = get_url(path);
  request->c = get_pooled_handle(request->url);
  request->response.memory = g_malloc0(1);
  request->response.size = 0;

  return request;
} 

static int
free_request(HTTP_REQUEST *request)
{
  g_free(request->response.memory);
  release_pooled_handle(request->c);
  g_free(request->url);
  g_free(request->path);
  curl_slist_free_all(request->headers);
  g_free(request);

  return 0;
}

int
stormfs_curl_delete(const char *path)
{
  int result;
  HTTP_REQUEST *request = new_request(path);

  sign_request("DELETE", &request->headers, request->path);
  curl_easy_setopt(request->c, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);

  result = stormfs_curl_easy_perform(request->c);
  free_request(request);

  return result;
}

int
stormfs_curl_get(const char *path, char **data)
{
  int result;
  HTTP_REQUEST *request = new_request(path);

  sign_request("GET", &request->headers, request->path);
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);
  curl_easy_setopt(request->c, CURLOPT_WRITEDATA, (void *) &request->response);
  curl_easy_setopt(request->c, CURLOPT_WRITEFUNCTION, write_memory_cb);

  result = stormfs_curl_easy_perform(request->c);

  *data = strdup(request->response.memory);
  free_request(request);

  return result;
}

int
stormfs_curl_get_file(const char *path, FILE *f)
{
  int result;
  char *url = get_url(path);
  CURL *c = get_pooled_handle(url);
  struct curl_slist *req_headers = NULL;

  sign_request("GET", &req_headers, path);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, f);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);

  result = stormfs_curl_easy_perform(c);
  rewind(f);

  g_free(url);
  release_pooled_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

int
stormfs_curl_head(const char *path, GList **headers)
{
  int result;
  char *url = get_url(path);
  char *response_headers;
  CURL *c = get_pooled_handle(url);
  struct curl_slist *req_headers = NULL;
  HTTP_RESPONSE data;

  data.memory = g_malloc(1);
  data.size = 0;

  pthread_mutex_lock(&lock);
  sign_request("HEAD", &req_headers, path);
  pthread_mutex_unlock(&lock);
  curl_easy_setopt(c, CURLOPT_NOBODY, 1L);    // HEAD
  curl_easy_setopt(c, CURLOPT_FILETIME, 1L);  // Last-Modified
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, (void *) &data);
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, write_memory_cb);

  result = stormfs_curl_easy_perform(c);

  response_headers = strdup(data.memory);
  pthread_mutex_lock(&lock);
  extract_meta(response_headers, &(*headers));
  pthread_mutex_unlock(&lock);

  g_free(url);
  g_free(data.memory);
  g_free(response_headers);
  release_pooled_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

int
stormfs_curl_head_multi(const char *path, GList *files)
{
  int running_handles;
  size_t i, n_running, last_req_idx = 0;
  size_t n_files = g_list_length(files);
  HTTP_REQUEST *requests = g_new0(HTTP_REQUEST, n_files);
  GList *head = NULL, *next = NULL;

  i = 0;
  n_running = 0;
  head = g_list_first(files);
  while(head != NULL) {
    next = head->next;
    struct file *f = head->data;

    CURLMcode err;
    requests[i].headers = NULL;
    requests[i].response.memory = g_malloc0(1);
    requests[i].response.size = 0;
    requests[i].path = get_path(path, f->name);
    requests[i].done = false;

    if(n_running < MAX_REQUESTS && n_running < n_files) {
      char *url = get_url(requests[i].path);
      requests[i].c = get_pooled_handle(url);
      sign_request("HEAD", &requests[i].headers, requests[i].path);
      curl_easy_setopt(requests[i].c, CURLOPT_NOBODY, 1L);    // HEAD
      curl_easy_setopt(requests[i].c, CURLOPT_FILETIME, 1L);  // Last-Modified
      curl_easy_setopt(requests[i].c, CURLOPT_HTTPHEADER, requests[i].headers);
      curl_easy_setopt(requests[i].c, CURLOPT_HEADERDATA, (void *) &requests[i].response);
      curl_easy_setopt(requests[i].c, CURLOPT_HEADERFUNCTION, write_memory_cb);
      g_free(url);

      if((err = curl_multi_add_handle(curl.multi, requests[i].c)) != CURLM_OK)
        return -EIO;

      n_running++;
      last_req_idx = i;
    }

    i++;
    head = next;
  }

  curl_multi_perform(curl.multi, &running_handles);
  while(running_handles) {
    if(running_handles) {
      int max_fd = -1;
      long curl_timeout = -1;
      struct timeval timeout;
      CURLMcode err;

      fd_set fd_r;
      fd_set fd_w;
      fd_set fd_e;
      FD_ZERO(&fd_r);
      FD_ZERO(&fd_w);
      FD_ZERO(&fd_e);
      timeout.tv_sec  = 1;
      timeout.tv_usec = 0;

      curl_multi_timeout(curl.multi, &curl_timeout);
      if(curl_timeout >= 0) {
        timeout.tv_sec = curl_timeout / 1000;
        if(timeout.tv_sec > 1)
          timeout.tv_sec = 1;
        else
          timeout.tv_usec = (curl_timeout % 1000) * 1000;
      }

      err = curl_multi_fdset(curl.multi, &fd_r, &fd_w, &fd_e, &max_fd);
      if(err != CURLM_OK)
        return -EIO;

      if(select(max_fd + 1, &fd_r, &fd_w, &fd_e, &timeout) == -1)
        return -errno;
    }

    curl_multi_perform(curl.multi, &running_handles);

    CURLMsg *msg;
    int remaining;
    while((msg = curl_multi_info_read(curl.multi, &remaining))) {
      if(msg->msg != CURLMSG_DONE)
        continue;

      for(i = 0; i < n_files; i++) {
        // requests *might* share the same handle out of the pool,
        // make sure the request hasn't also been marked as completed
        if(msg->easy_handle == requests[i].c && !requests[i].done)
          break;
      }

      struct file *f = g_list_nth_data(files, i);
      extract_meta(requests[i].response.memory, &(f->headers));
      g_free(requests[i].response.memory);
      curl_slist_free_all(requests[i].headers);
      curl_multi_remove_handle(curl.multi, requests[i].c);
      release_pooled_handle(requests[i].c);
      requests[i].done = true;
      n_running--;

      if(n_running < MAX_REQUESTS && last_req_idx < (n_files - 1)) {
        CURLMcode err;
        last_req_idx++;;

        char *url = get_url(requests[last_req_idx].path);
        requests[last_req_idx].c = get_pooled_handle(url);
        sign_request("HEAD", &requests[last_req_idx].headers, requests[last_req_idx].path);
        curl_easy_setopt(requests[last_req_idx].c, CURLOPT_NOBODY, 1L);    // HEAD
        curl_easy_setopt(requests[last_req_idx].c, CURLOPT_FILETIME, 1L);  // Last-Modified
        curl_easy_setopt(requests[last_req_idx].c, CURLOPT_HTTPHEADER, requests[last_req_idx].headers);
        curl_easy_setopt(requests[last_req_idx].c, CURLOPT_HEADERDATA, (void *) &requests[last_req_idx].response);
        curl_easy_setopt(requests[last_req_idx].c, CURLOPT_HEADERFUNCTION, write_memory_cb);
        g_free(url);

        if((err = curl_multi_add_handle(curl.multi, requests[last_req_idx].c)) != CURLM_OK)
          return -EIO;

        n_running++;
      }
    }
  }

  for(i = 0; i < n_files; i++) {
    if(requests[i].c != NULL)
      release_pooled_handle(requests[i].c);
    g_free(requests[i].path);
  }
  g_free(requests);

  return 0;
}

int
stormfs_curl_list_bucket(const char *path, char **xml)
{
  int result;
  char *marker = g_strdup("");
  bool truncated = TRUE;

  while(truncated) {
    char *url = get_list_bucket_url(path, marker);
    CURL *c = get_pooled_handle(url);
    struct curl_slist *req_headers = NULL;
    HTTP_RESPONSE body;

    body.memory = g_malloc(1);
    body.size = 0;

    sign_request("GET", &req_headers, "/");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *) &body);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_memory_cb);

    result = stormfs_curl_easy_perform(c);

    if(*xml == NULL)
      *xml = strdup(body.memory);
    else
      *xml = append_list_bucket_xml(*xml, body.memory);

    if((truncated = is_truncated(body.memory)) == true) {
      g_free(marker);
      marker = get_next_marker(body.memory);
    }

    g_free(url);
    g_free(body.memory);
    release_pooled_handle(c);
    curl_slist_free_all(req_headers);
  }

  g_free(marker);

  return result;
}

int
stormfs_curl_upload(const char *path, GList *headers, int fd)
{
  FILE *f;
  int result;
  char *url;
  CURL *c;
  struct stat st;
  struct curl_slist *req_headers = NULL;

  if(fstat(fd, &st) != 0) {
    perror("fstat");
    return -errno;
  }

  // TODO: support multipart uploads (>5GB files)
  if(st.st_size >= FIVE_GB)
    return -EFBIG;

  if(lseek(fd, 0, SEEK_SET) == -1) {
    perror("lseek");
    return -errno;
  }

  if((f = fdopen(fd, "rb")) == NULL) {
    perror("fdopen");
    return -errno;
  }

  url = get_url(path);
  c = get_pooled_handle(url);
  req_headers = headers_to_curl_slist(headers);

  sign_request("PUT", &req_headers, path);
  curl_easy_setopt(c, CURLOPT_INFILE, f);
  curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(c, CURLOPT_INFILESIZE_LARGE, (curl_off_t) st.st_size);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  result = stormfs_curl_easy_perform(c);

  g_free(url);
  release_pooled_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

int
stormfs_curl_put_headers(const char *path, GList *headers)
{
  int result;
  char *url = get_url(path);
  CURL *c = get_pooled_handle(url);
  struct curl_slist *req_headers = NULL;
  HTTP_RESPONSE body;

  body.memory = g_malloc(1);
  body.size = 0;

  req_headers = headers_to_curl_slist(headers);

  sign_request("PUT", &req_headers, path);
  curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);    // HTTP PUT
  curl_easy_setopt(c, CURLOPT_INFILESIZE, 0); // Content-Length: 0
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *) &body);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_memory_cb);

  result = stormfs_curl_easy_perform(c);

  g_free(url);
  g_free(body.memory);
  release_pooled_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

int
stormfs_curl_set_auth(const char *access_key, const char *secret_key)
{
  curl.access_key = access_key;
  curl.secret_key = secret_key;

  return 0;
}

int
stormfs_curl_verify_ssl(int verify)
{
  if(verify == 0)
    curl.verify_ssl = 0;
  else
    curl.verify_ssl = 1;

  return 0;
}

void
stormfs_curl_destroy()
{
  destroy_pool();
  curl_share_cleanup(curl.share);
  curl_multi_cleanup(curl.multi);
  curl_global_cleanup();
}

static int
multi_init()
{
  if((curl.multi = curl_multi_init()) == NULL)
    return -1;

  return 0;
}

static int
share_init()
{
  CURLSHcode scode = CURLSHE_OK;
  if((curl.share = curl_share_init()) == NULL)
    return -1;
  if((scode = curl_share_setopt(curl.share,
          CURLSHOPT_LOCKFUNC, share_lock)) != CURLSHE_OK)
    return -1;
  if((scode = curl_share_setopt(curl.share,
          CURLSHOPT_UNLOCKFUNC, share_unlock)) != CURLSHE_OK)
    return -1;
  if((scode = curl_share_setopt(curl.share,
          CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS)) != CURLSHE_OK)
    return -1;

  return 0;
}

int
stormfs_curl_init(const char *bucket, const char *url)
{
  CURLcode result;
  curl.url = url;
  curl.bucket = bucket;
  curl.verify_ssl = 1;

  if((result = curl_global_init(CURL_GLOBAL_ALL)) != CURLE_OK)
    return -1;
  if(share_init() != 0)
    return -1;
  if(multi_init() != 0)
    return -1;
  if(pool_init() != 0);

  return 0;
}
