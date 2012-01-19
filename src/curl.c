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
#include <sys/time.h>
#include <sys/select.h>
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
#define MULTIPART_MIN     20971520 /* Minimum size for multipart files */
#define MULTIPART_CHUNK   10485760 /* 10MB */
#define MAX_FILE_SIZE     104857600000 /* 97.65GB (10,000 * 10MB) */

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
  int fd;
  int part_num;
  char *path;
  char *etag;
  char *upload_id;
  off_t size;
} FILE_PART;

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

struct post_data {
  const char *readptr;
  int remaining;
};

static char *
gid_to_s(gid_t gid)
{
  char s[100];
  snprintf(s, 100, "%lu", (unsigned long) gid);

  return strdup(s);
}

static char *
rdev_to_s(dev_t rdev)
{
  char s[100];
  snprintf(s, 100, "%lu", (unsigned long) rdev);

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

static FILE_PART *
create_part(int part_num, char *upload_id)
{
  FILE_PART *fp = g_new0(FILE_PART, 1);

  fp->part_num = part_num;
  fp->upload_id = strdup(upload_id);
  fp->path = strdup("/tmp/stormfs.XXXXXX");
  if((fp->fd = mkstemp(fp->path)) == -1) {
    perror("mkstemp");
    free(fp->path);
    free(fp);
    return NULL;
  }

  return fp;
}

static void
free_part(FILE_PART *fp)
{
  free(fp->path);
  free(fp->etag);
  free(fp->upload_id);
  free(fp);
}

void
free_parts(GList *parts)
{
  g_list_free_full(parts, (GDestroyNotify) free_part);
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
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-acl");
  h->value = strdup(acl);

  return h;
}

HTTP_HEADER *
content_header(const char *type)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

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
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

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
  char *s = time_to_s(t);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-meta-ctime");
  h->value = s;

  return h;
}

HTTP_HEADER *
expires_header(const char *expires)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("Expires");
  h->value = strdup(expires);

  return h;
}

HTTP_HEADER *
gid_header(gid_t gid)
{
  char *s = gid_to_s(gid);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("x-amz-meta-gid");
  h->value = s;

  return h;
}

HTTP_HEADER *
rdev_header(dev_t rdev)
{
  char *s = rdev_to_s(rdev);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("x-amz-meta-rdev");
  h->value = s;

  return h;
}

HTTP_HEADER *
mode_header(mode_t mode)
{
  char *s = mode_to_s(mode);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("x-amz-meta-mode");
  h->value = s;

  return h;
}

HTTP_HEADER *
mtime_header(time_t t)
{
  char *s = time_to_s(t);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-meta-mtime");
  h->value = s;

  return h;
}

HTTP_HEADER *
replace_header()
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("x-amz-metadata-directive");
  h->value = strdup("REPLACE");

  return h;
}

HTTP_HEADER *
storage_header(const char *class)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-storage-class");
  h->value = strdup(class);

  return h;
}

HTTP_HEADER *
uid_header(uid_t uid)
{
  char *s = uid_to_s(uid);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

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
      headers = g_list_remove(headers, head->data);

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

static char *
get_upload_id(char *xml)
{
  char *start_marker = "UploadId>";
  char *end_marker  = "</UploadId";
  char *start_p, *end_p;

  start_p = strstr(xml, start_marker) + strlen(start_marker);
  end_p   = strstr(xml, end_marker);

  return strndup(start_p, end_p - start_p);
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
  xml = realloc(xml, sizeof(char) *
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
    free(s);

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
      amz_headers = realloc(amz_headers, sizeof(char) * strlen(amz_headers) +
                        strlen(header->data) + 2);
      amz_headers = strncat(amz_headers, header->data, strlen(header->data));
      amz_headers = strncat(amz_headers, "\n", 1);
    } else if(strstr(header->data, "Content-Type") != NULL) {
      char *tmp = strstr(header->data, ":") + 1;
      content_type = realloc(content_type, sizeof(char) * strlen(content_type) +
                        strlen(content_type) + strlen(tmp) + 2);
      content_type = strncat(content_type, tmp, strlen(tmp));
    }

    header = next;
  }

  asprintf(&to_sign, "%s\n\n%s\n%s\n%s%s", 
      method, content_type, date, amz_headers, resource);

  signature = hmac_sha1(curl.secret_key, to_sign);

  asprintf(&authorization, "Authorization: AWS %s:%s",
      curl.access_key, signature);

  asprintf(&date_header, "Date: %s", date);
  *headers = curl_slist_append(*headers, date_header);
  *headers = curl_slist_append(*headers, authorization);

  free(date);
  free(resource);
  free(signature);
  free(to_sign);
  free(amz_headers);
  free(date_header);
  free(content_type);
  free(authorization);

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
  char *url;
  char *encoded_path = url_encode((char *) path);

  asprintf(&url, "%s%s?delimiter=/", curl.url, encoded_path);
  free(encoded_path);

  return url;
}

static char *
get_multipart_url(const char *path)
{
  char *url;
  char *encoded_path = url_encode((char *) path);

  asprintf(&url, "%s%s?uploads", curl.url, encoded_path);
  free(encoded_path);

  return url;
}

static char *
get_upload_part_url(const char *path, FILE_PART *fp)
{
  char *url;
  char *encoded_path = url_encode((char *) path);

  asprintf(&url, "%s%s?partNumber=%d&uploadId=%s",
      curl.url, encoded_path, fp->part_num, fp->upload_id);
  free(encoded_path);

  return url;
}

static char *
get_complete_multipart_url(const char *path, char *upload_id)
{
  char *url;
  char *encoded_path = url_encode((char *) path);

  asprintf(&url, "%s%s?uploadId=%s",
      curl.url, encoded_path, upload_id);
  free(encoded_path);

  return url;
}

static char *
get_list_bucket_url(const char *path, const char *next_marker)
{
  char *url;
  char *encoded_path = url_encode((char *) path);

  if(strlen(path) > 1)
    asprintf(&url, "%s?delimiter=/&marker=%s&prefix=%s/",
        curl.url, next_marker, encoded_path + 1);
  else
    asprintf(&url, "%s?delimiter=/&marker=%s&prefix=",
        curl.url, next_marker);

  free(encoded_path);

  return url;
}

static size_t
read_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct post_data *pd = userp;

  if(size*nmemb < 1)
    return 0;

  if(pd->remaining) {
    *(char *)ptr = pd->readptr[0];
    pd->readptr++;
    pd->remaining--;
    return 1;
  }

  return 0;
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
  char *to_extract[10] = {
    "Content-Type",
    "Content-Length",
    "Last-Modified",
    "ETag",
    "x-amz-meta-gid",
    "x-amz-meta-uid",
    "x-amz-meta-rdev",
    "x-amz-meta-mode",
    "x-amz-meta-ctime",
    "x-amz-meta-mtime"
  };

  p = strtok(headers, "\r\n");
  while(p != NULL) {
    int i;

    for(i = 0; i < 10; i++) {
      HTTP_HEADER *h;
      char *key = to_extract[i];
      char *value;

      if(!strstr(p, key))
        continue;

      h = g_malloc(sizeof(HTTP_HEADER));
      h->key = strdup(key);

      /* remove leading space */
      value = strstr(p, " ");
      value++;

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

  // no handles available in the pool, create a new one.
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
  request->path = strdup(path);
  request->url = get_url(path);
  request->c = get_pooled_handle(request->url);
  request->response.memory = g_malloc0(1);
  request->response.size = 0;

  return request;
}

static int
free_request(HTTP_REQUEST *request)
{
  free(request->response.memory);
  release_pooled_handle(request->c);
  free(request->url);
  free(request->path);
  curl_slist_free_all(request->headers);
  free(request);

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
  HTTP_REQUEST *request = new_request(path);

  sign_request("GET", &request->headers, path);
  curl_easy_setopt(request->c, CURLOPT_WRITEDATA, f);
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);
  result = stormfs_curl_easy_perform(request->c);

  rewind(f);
  free_request(request);

  return result;
}

int
stormfs_curl_head(const char *path, GList **headers)
{
  int result;
  HTTP_REQUEST *request = new_request(path);

  sign_request("HEAD", &request->headers, request->path);
  curl_easy_setopt(request->c, CURLOPT_NOBODY, 1L);    // HEAD
  curl_easy_setopt(request->c, CURLOPT_FILETIME, 1L);  // Last-Modified
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);
  curl_easy_setopt(request->c, CURLOPT_HEADERDATA, (void *) &request->response);
  curl_easy_setopt(request->c, CURLOPT_HEADERFUNCTION, write_memory_cb);
  result = stormfs_curl_easy_perform(request->c);

  extract_meta(request->response.memory, &(*headers));
  free_request(request);

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
      free(marker);
      marker = get_next_marker(body.memory);
    }

    free(url);
    free(body.memory);
    release_pooled_handle(c);
    curl_slist_free_all(req_headers);
  }

  free(marker);

  return result;
}

static int
upload_part(const char *path, FILE_PART *fp)
{
  int result;
  FILE *f;
  CURL *c;
  char *url;
  char *sign_path;
  HTTP_RESPONSE response;
  struct curl_slist *req_headers = NULL;
  struct stat st;
  GList *headers = NULL, *head = NULL, *next = NULL;

  if(fstat(fp->fd, &st) != 0) {
    perror("fstat");
    return -errno;
  }

  if(lseek(fp->fd, 0, SEEK_SET) == -1) {
    perror("lseek");
    return -errno;
  }

  if((f = fdopen(fp->fd, "rb")) == NULL) {
    perror("fdopen");
    return -errno;
  }

  response.memory = malloc(1);
  response.size = 0;
  url = get_upload_part_url(path, fp);
  c = get_pooled_handle(url);

  asprintf(&sign_path, "%s?partNumber=%d&uploadId=%s",
      path, fp->part_num, fp->upload_id);

  sign_request("PUT", &req_headers, sign_path);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_INFILE, f);
  curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(c, CURLOPT_INFILESIZE_LARGE, (curl_off_t) st.st_size);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, (void *) &response);
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, write_memory_cb);
  result = stormfs_curl_easy_perform(c);

  extract_meta(response.memory, &headers);

  head = g_list_first(headers);
  while(head != NULL) {
    next = head->next;
    HTTP_HEADER *h = head->data;
    if(strstr(h->key, "ETag") != NULL) {
      fp->etag = strdup(h->value);
      break;
    }

    head = next;
  }

  free(url);
  free(sign_path);
  free(response.memory);
  free_headers(headers);
  curl_slist_free_all(req_headers);
  release_pooled_handle(c);

  return result;
}

static char *
complete_multipart_xml(GList *parts)
{
  GList *head = NULL, *next = NULL;
  char *xml = strdup("<CompleteMultipartUpload>\n");

  xml = realloc(xml, sizeof(char) *
      strlen(xml) + (g_list_length(parts) * 150));

  head = g_list_first(parts);
  while(head != NULL) {
    next = head->next;
    FILE_PART *fp = head->data;
    char *part_xml;

    asprintf(&part_xml, "  <Part>\n"
                        "    <PartNumber>%d</PartNumber>\n"
                        "    <ETag>%s</ETag>\n"
                        "  </Part>\n",
        fp->part_num, fp->etag);
    xml = strncat(xml, part_xml, strlen(part_xml));

    free(part_xml);
    head = next;
  }

  xml = g_realloc(xml, strlen(xml) + 27);
  xml = strcat(xml, "</CompleteMultipartUpload>\n");

  return xml;
}

static int
complete_multipart(const char *path, char *upload_id,
    GList *headers, GList *parts)
{
  int result;
  CURL *c;
  char *url;
  char *sign_path;
  HTTP_RESPONSE body;
  struct curl_slist *req_headers = NULL;
  char *xml = complete_multipart_xml(parts);
  char *post = strdup(xml);
  struct post_data pd;
  GList *stripped_headers = NULL;

  body.memory = g_malloc(1);
  body.size = 0;

  pd.readptr = post;
  pd.remaining = strlen(post);

  asprintf(&sign_path, "%s?uploadId=%s", path, upload_id);

  url = get_complete_multipart_url(path, upload_id);
  c = get_pooled_handle(url);
  headers = g_list_first(headers);
  stripped_headers = g_list_copy(headers);
  stripped_headers = strip_header(stripped_headers, "x-amz");
  req_headers = headers_to_curl_slist(stripped_headers);

  sign_request("POST", &req_headers, sign_path);
  curl_easy_setopt(c, CURLOPT_POST, 1L);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *) &body);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_memory_cb);
  curl_easy_setopt(c, CURLOPT_READDATA, &pd);
  curl_easy_setopt(c, CURLOPT_READFUNCTION, read_callback);
  curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) pd.remaining);

  result = stormfs_curl_easy_perform(c);

  free(url);
  free(sign_path);
  free(xml);
  free(post);
  free(body.memory);
  curl_slist_free_all(req_headers);
  release_pooled_handle(c);

  return 0;
}

static char *
init_multipart(const char *path, off_t size, GList *headers)
{
  int result;
  CURL *c;
  char *url;
  char *sign_path;
  char *uploads = "?uploads";
  char *upload_id = NULL;
  HTTP_RESPONSE body;
  struct curl_slist *req_headers = NULL;

  body.memory = g_malloc(1);
  body.size = 0;

  sign_path = malloc(sizeof(char) *
      strlen(path) + strlen(uploads) + 1);
  sign_path = strcpy(sign_path, path);
  sign_path = strncat(sign_path, uploads, strlen(uploads));

  url = get_multipart_url(path);
  c = get_pooled_handle(url);
  headers = g_list_first(headers);
  req_headers = headers_to_curl_slist(headers);

  sign_request("POST", &req_headers, sign_path);
  curl_easy_setopt(c, CURLOPT_POST, true);
  curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, 0);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *) &body);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_memory_cb);

  result = stormfs_curl_easy_perform(c);

  free(url);
  free(sign_path);
  curl_slist_free_all(req_headers);
  release_pooled_handle(c);
  if(result != 0) {
    free(body.memory);
    return NULL;
  }

  upload_id = get_upload_id(body.memory);

  free(body.memory);

  return upload_id;
}

static GList *
create_file_parts(const char *path, char *upload_id, int fd)
{
  FILE *f;
  struct stat st;
  off_t bytes_remaining;
  GList *parts = NULL;

  if(fstat(fd, &st) != 0) {
    perror("fstat");
    return NULL;
  }

  if((f = fdopen(fd, "rb")) == NULL) {
    perror("fdopen");
    return NULL;
  }

  int part_num = 1;
  bytes_remaining = st.st_size;
  while(bytes_remaining > 0) {
    char *buf;
    size_t nbytes;
    FILE *tmp_f;
    FILE_PART *fp = create_part(part_num, upload_id);

    if(bytes_remaining > MULTIPART_CHUNK)
      fp->size = MULTIPART_CHUNK;
    else
      fp->size = bytes_remaining;

    if((buf = malloc(sizeof(char) * fp->size)) == NULL) {
      perror("malloc");
      return NULL;
    }

    if((tmp_f = fdopen(fp->fd, "wb")) == NULL) {
      perror("fdopen");
      return NULL;
    }

    if((nbytes = fread(buf, 1, fp->size, f)) != fp->size) {
      free(buf);
      return NULL;
    }

    nbytes = fwrite(buf, 1, fp->size, tmp_f);
    free(buf);
    if(nbytes != fp->size)
      return NULL;

    parts = g_list_append(parts, fp);
    part_num++;
    bytes_remaining = bytes_remaining - fp->size;
  }

  return parts;
}

static int
upload_multipart(const char *path, GList *headers, int fd)
{
  int result;
  struct stat st;
  char *upload_id = NULL;
  GList *parts = NULL, *head = NULL, *next = NULL;

  if(fstat(fd, &st) != 0) {
    perror("fstat");
    return -errno;
  }

  if(lseek(fd, 0, SEEK_SET) == -1) {
    perror("lseek");
    return -errno;
  }

  if((upload_id = init_multipart(path, st.st_size, headers)) == NULL)
    return -EIO;

  if((parts = create_file_parts(path, upload_id, fd)) == NULL)
    return -EIO;

  head = g_list_first(parts);
  while(head != NULL) {
    next = head->next;
    FILE_PART *fp = head->data;
    result = upload_part(path, fp);
    close(fp->fd);
    unlink(fp->path);
    if(result != 0)
      break;

    head = next;
  }

  if(result != 0) {
    free_parts(parts);
    return result;
  }

  result = complete_multipart(path, upload_id, headers, parts);
  free_parts(parts);

  return result;
}

int
stormfs_curl_upload(const char *path, GList *headers, int fd)
{
  FILE *f;
  int result;
  struct stat st;
  HTTP_REQUEST *request;

  if(fstat(fd, &st) != 0) {
    perror("fstat");
    return -errno;
  }

  if(st.st_size >= MAX_FILE_SIZE)
    return -EFBIG;

  if(st.st_size >= MULTIPART_MIN)
    return upload_multipart(path, headers, fd);

  if(lseek(fd, 0, SEEK_SET) == -1) {
    perror("lseek");
    return -errno;
  }

  if((f = fdopen(fd, "rb")) == NULL) {
    perror("fdopen");
    return -errno;
  }

  request = new_request(path);
  request->headers = headers_to_curl_slist(headers);

  sign_request("PUT", &request->headers, request->path);
  curl_easy_setopt(request->c, CURLOPT_INFILE, f);
  curl_easy_setopt(request->c, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(request->c, CURLOPT_INFILESIZE_LARGE, (curl_off_t) st.st_size);
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);
  result = stormfs_curl_easy_perform(request->c);

  free_request(request);

  return result;
}

int
stormfs_curl_put(const char *path, GList *headers)
{
  int result;
  HTTP_REQUEST *request = new_request(path);
  request->headers = headers_to_curl_slist(headers);

  sign_request("PUT", &request->headers, request->path);
  curl_easy_setopt(request->c, CURLOPT_UPLOAD, 1L);    // HTTP PUT
  curl_easy_setopt(request->c, CURLOPT_INFILESIZE, 0); // Content-Length: 0
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);
  curl_easy_setopt(request->c, CURLOPT_WRITEDATA, (void *) &request->response);
  curl_easy_setopt(request->c, CURLOPT_WRITEFUNCTION, write_memory_cb);
  result = stormfs_curl_easy_perform(request->c);

  free_request(request);

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
  if(pool_init() != 0)
    return -1;

  return 0;
}
