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

struct stormfs_curl {
  int verify_ssl;
  const char *url;
  const char *bucket;
  const char *access_key;
  const char *secret_key;
  pthread_mutex_t lock;
} stormfs_curl;

typedef struct {
  char   *memory;
  size_t size;
} HTTP_RESPONSE;

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
    h->value = strdup("application/octet-stream");
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
  HTTP_HEADER *h = g_malloc(sizeof(HTTP_HEADER));

  h->key = strdup("x-amz-copy-source");
  h->value = get_resource(path);

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
  GList *new = NULL;
  GList *head = NULL;
  GList *next = NULL;

  head = g_list_first(headers);
  while(head != NULL) {
    next = head->next;
    HTTP_HEADER *header = head->data;

    if(strstr(header->key, key) != NULL) {
      g_free(header->key);
      g_free(header->value);
      g_free(header);

      head = next;
      continue;
    }

    HTTP_HEADER *h;
    h = g_malloc(sizeof(HTTP_HEADER));
    h->key   = strdup(header->key);
    h->value = strdup(header->value);

    g_free(header->key);
    g_free(header->value);
    g_free(header);

    new = g_list_append(new, h);
    head = next;
  }

  g_list_free(headers);

  return new;
}

GList *
add_header(GList *headers, HTTP_HEADER *h)
{
  headers = strip_header(headers, h->key);
  headers = g_list_append(headers, h);

  return headers;
}

static gboolean
is_truncated(char *xml)
{
  if(strstr(xml, "<IsTruncated>true"))
    return TRUE;

  return FALSE;
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
  s = g_malloc(sizeof(char) * strlen(h->key) + strlen(h->value) + 2);
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

    if(strstr(h->key, "x-amz-") != NULL || strstr(h->key, "Expires") != NULL)
      curl_headers = curl_slist_append(curl_headers, header_to_s(h));
    else if(strstr(h->key, "Content-Type") != NULL)
      curl_headers = curl_slist_append(curl_headers, header_to_s(h));

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
  strftime(s, sizeof(s), "%a, %d %b %Y %T %z", gmtime(&t));

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

  signature = hmac_sha1(stormfs_curl.secret_key, to_sign);
  
  authorization = g_malloc(sizeof(char) * strlen(stormfs_curl.access_key) +
                                          strlen(signature) + 22);
  authorization = strcpy(authorization, "Authorization: AWS ");
  authorization = strcat(authorization, stormfs_curl.access_key);
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
set_curl_defaults(CURL **c)
{
  curl_easy_setopt(*c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(*c, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(*c, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt(*c, CURLOPT_USERAGENT, "stormfs");
  curl_easy_setopt(*c, CURLOPT_DNS_CACHE_TIMEOUT, -1);
  curl_easy_setopt(*c, CURLOPT_SSL_VERIFYHOST, stormfs_curl.verify_ssl);

  // curl_easy_setopt(*c, CURLOPT_VERBOSE, 1L);
  // curl_easy_setopt(*c, CURLOPT_FORBID_REUSE, 1);

  return 0;
}

static char *
get_url(const char *path)
{
  char *tmp = url_encode((char *) path);
  char *delimiter = "?delimiter=/";
  char *url = g_malloc(sizeof(char) * 
      strlen(stormfs_curl.url) +
      strlen(tmp) + 
      strlen(delimiter) + 1);
  
  url = strcpy(url, stormfs_curl.url);
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
  size_t url_len         = strlen(stormfs_curl.url);
  size_t delimiter_len   = strlen(delimiter);
  size_t prefix_len      = strlen(prefix);
  size_t path_len        = strlen(path);
  size_t marker_len      = strlen(marker) + strlen(next_marker);

  tmp = g_malloc(sizeof(char) * (url_len + delimiter_len +
      marker_len + prefix_len + 1));

  tmp = strcpy(tmp, stormfs_curl.url);
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
stormfs_curl_delete(const char *path)
{
  int result;
  char *url = get_url(path);
  CURL *c = get_curl_handle(url);
  struct curl_slist *req_headers = NULL; 

  sign_request("DELETE", &req_headers, path);
  curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);

  result = stormfs_curl_easy_perform(c);
  destroy_curl_handle(c);

  return result;
}

int
stormfs_curl_init(const char *bucket, const char *url)
{
  CURLcode result;
  stormfs_curl.url = url;
  stormfs_curl.bucket = bucket;
  stormfs_curl.verify_ssl = 1;
  pthread_mutex_init(&stormfs_curl.lock, NULL);

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
stormfs_curl_verify_ssl(int verify)
{
  if(verify == 0)
    stormfs_curl.verify_ssl = 0;
  else
    stormfs_curl.verify_ssl = 1;

  return 0;
}

int
stormfs_curl_get(const char *path, char **data)
{
  int result;
  char *url = get_url(path);
  CURL *c = get_curl_handle(url);
  struct curl_slist *req_headers = NULL; 
  HTTP_RESPONSE body;

  body.memory = g_malloc(1);
  body.size = 0;

  sign_request("GET", &req_headers, path);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *) &body);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_memory_cb);

  result = stormfs_curl_easy_perform(c);

  *data = strdup(body.memory);

  g_free(url);
  g_free(body.memory);
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

int
stormfs_curl_get_file(const char *path, FILE *f)
{
  int result;
  char *url = get_url(path);
  CURL *c = get_curl_handle(url);
  struct curl_slist *req_headers = NULL; 

  sign_request("GET", &req_headers, path);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, f);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);

  result = stormfs_curl_easy_perform(c);
  rewind(f);

  g_free(url);
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

int
stormfs_curl_head(const char *path, GList **headers)
{
  int result;
  char *url = get_url(path);
  char *response_headers;
  CURL *c = get_curl_handle(url);
  struct curl_slist *req_headers = NULL;
  HTTP_RESPONSE data;

  data.memory = g_malloc(1);
  data.size = 0;

  pthread_mutex_lock(&stormfs_curl.lock);
  sign_request("HEAD", &req_headers, path);
  pthread_mutex_unlock(&stormfs_curl.lock);
  curl_easy_setopt(c, CURLOPT_NOBODY, 1L);    // HEAD
  curl_easy_setopt(c, CURLOPT_FILETIME, 1L);  // Last-Modified
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, (void *) &data);
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, write_memory_cb);

  result = stormfs_curl_easy_perform(c);

  response_headers = strdup(data.memory);
  pthread_mutex_lock(&stormfs_curl.lock);
  extract_meta(response_headers, &(*headers));
  pthread_mutex_unlock(&stormfs_curl.lock);

  g_free(url);
  g_free(data.memory);
  g_free(response_headers);
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

int
stormfs_curl_head_multi(const char *path, GList *files)
{
  int running_handles;
  size_t i, n_running, last_req_idx = 0;
  size_t n_files = g_list_length(files);
  CURL *c[n_files];
  HTTP_RESPONSE *responses;
  struct curl_slist *req_headers[n_files];
  CURLM *multi;
  GList *head = NULL, *next = NULL;

  responses = g_malloc0(sizeof(HTTP_RESPONSE) * n_files);

  if((multi = curl_multi_init()) == NULL)
    return -1;

  i = 0;
  n_running = 0;
  head = g_list_first(files);
  while(head != NULL) {
    next = head->next;
    struct file *f = head->data;

    CURLMcode err;
    char *full_path = get_path(path, f->name);
    char *url = get_url(full_path);
    c[i] = get_curl_handle(url);
    req_headers[i] = NULL;
    responses[i].memory = g_malloc0(1);
    responses[i].size = 0;

    sign_request("HEAD", &req_headers[i], full_path);
    curl_easy_setopt(c[i], CURLOPT_NOBODY, 1L);    // HEAD
    curl_easy_setopt(c[i], CURLOPT_FILETIME, 1L);  // Last-Modified
    curl_easy_setopt(c[i], CURLOPT_HTTPHEADER, req_headers[i]);
    curl_easy_setopt(c[i], CURLOPT_HEADERDATA, (void *) &responses[i]);
    curl_easy_setopt(c[i], CURLOPT_HEADERFUNCTION, write_memory_cb);

    if(n_running < MAX_REQUESTS && n_running < n_files) {
      if((err = curl_multi_add_handle(multi, c[i])) != CURLM_OK)
        return -EIO;

      n_running++;
      last_req_idx = i;
    }

    g_free(full_path);
    g_free(url);

    i++;
    head = next;
  }

  curl_multi_perform(multi, &running_handles);
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

      curl_multi_timeout(multi, &curl_timeout);
      if(curl_timeout >= 0) {
        timeout.tv_sec = curl_timeout / 1000;
        if(timeout.tv_sec > 1)
          timeout.tv_sec = 1;
        else 
          timeout.tv_usec = (curl_timeout % 1000) * 1000;
      }

      err = curl_multi_fdset(multi, &fd_r, &fd_w, &fd_e, &max_fd);
      if(err != CURLM_OK)
        return -EIO;

      if(select(max_fd + 1, &fd_r, &fd_w, &fd_e, &timeout) == -1)
        return -errno;
    }

    curl_multi_perform(multi, &running_handles);

    CURLMsg *msg;
    int remaining;
    while((msg = curl_multi_info_read(multi, &remaining))) {
      if(msg->msg != CURLMSG_DONE)
        continue;

      for(i = 0; i < n_files; i++) {
        if(msg->easy_handle == c[i])
          break;
      }

      struct file *f = g_list_nth_data(files, i);
      extract_meta(responses[i].memory, &(f->headers));
      g_free(responses[i].memory);
      curl_slist_free_all(req_headers[i]);
      n_running--;

      if(n_running < MAX_REQUESTS && last_req_idx < (n_files - 1)) {
        CURLMcode err;
        last_req_idx++;;
        if((err = curl_multi_add_handle(multi, c[last_req_idx])) != CURLM_OK)
          return -EIO;

        n_running++;
      }
    }
  }

  g_free(responses);
  curl_multi_cleanup(multi);
  for(i = 0; i < n_files; i++)
    destroy_curl_handle(c[i]);

  return 0;
}

int
stormfs_curl_list_bucket(const char *path, char **xml)
{
  int result;
  char *marker = g_strdup("");
  gboolean truncated = TRUE;

  while(truncated) {
    char *url = get_list_bucket_url(path, marker);
    CURL *c = get_curl_handle(url);
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

    if((truncated = is_truncated(body.memory)) == TRUE) {
      g_free(marker);
      marker = get_next_marker(body.memory);
    }

    g_free(url);
    g_free(body.memory);
    destroy_curl_handle(c);
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

  if(fstat(fd, &st) != 0)
    return -errno;

  // TODO: support multipart uploads (>5GB files)
  if(st.st_size >= FIVE_GB)
    return -EFBIG;
  
  if((f = fdopen(fd, "rb")) == NULL)
    return -errno;

  url = get_url(path);
  c = get_curl_handle(url);

  req_headers = headers_to_curl_slist(headers);

  sign_request("PUT", &req_headers, path);
  curl_easy_setopt(c, CURLOPT_INFILE, f);
  curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(c, CURLOPT_INFILESIZE_LARGE, (curl_off_t) st.st_size); 
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);

  result = stormfs_curl_easy_perform(c);

  g_free(url);
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

int
stormfs_curl_put_headers(const char *path, GList *headers)
{
  int result;
  char *url = get_url(path);
  CURL *c = get_curl_handle(url);
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
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

void
stormfs_curl_destroy()
{
  pthread_mutex_destroy(&stormfs_curl.lock);
  curl_global_cleanup();
}
