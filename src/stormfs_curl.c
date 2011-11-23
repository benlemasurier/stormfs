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
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <pthread.h>
#include <glib.h>
#include "stormfs_curl.h"

#define SHA1_BLOCK_SIZE 64
#define SHA1_LENGTH 20

struct curl_global {
  CURLM *multi;
  guint timer_event;
  int still_running;
}; 

struct curl_connection_info {
  CURL *easy;
  const char *url;
  struct curl_global *global;
  char error[CURL_ERROR_SIZE];
};

struct curl_socket_info {
  curl_socket_t sockfd;
  CURL *easy;
  int action;
  long timeout;
  GIOChannel *io_channel;
  guint ev;
  struct curl_global *global;
};

struct stormfs_curl {
  int fifo;
  int verify_ssl;
  const char *url;
  const char *bucket;
  const char *access_key;
  const char *secret_key;
  char *fifo_path;
  GIOChannel *io_channel;
  struct curl_global *curl_global;
  pthread_t event_thread;
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
free_headers(HTTP_HEADER *h)
{
  g_free(h->key);
  g_free(h->value);
  g_free(h);
}

int
init_fifo(void)
{
  int fd;

  if(mkstemp(stormfs_curl.fifo_path) == -1) {
    perror("mkstemp");
    abort();
  }

  unlink(stormfs_curl.fifo_path);
  if(mkfifo(stormfs_curl.fifo_path, 0600) == -1) {
    perror("mkfifo");
    abort();
  }

  fd = open(stormfs_curl.fifo_path, O_RDWR | O_NONBLOCK, 0);
  if(fd == -1) {
    perror("open");
    abort();
  }

  return fd;
}

char *
url_encode(char *s)
{
  char *p = s;
  char *buf = g_malloc((strlen(s) * 3) + 1);
  char *pbuf = buf;

  while(*p) {
    if(isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') 
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

    if(strstr(h->key, "x-amz-") != NULL)
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
http_response_errno(CURL *handle)
{
  long http_response;

  if(curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_response) != 0)
    return -EIO;

  if(http_response == 401)
    return -EACCES;

  if(http_response == 403)
    return -EACCES;

  if(http_response == 404)
    return -ENOENT;

  if(http_response >= 400)
    return -EIO; 

  return 0;
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

HTTP_HEADER *
content_header(const char *type)
{
  HTTP_HEADER *h;
  h = g_malloc(sizeof(HTTP_HEADER));

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
  HTTP_HEADER *h;
  h = g_malloc(sizeof(HTTP_HEADER));

  h->key   = strdup("x-amz-metadata-directive");
  h->value = strdup("COPY");

  return h;
}

HTTP_HEADER *
copy_source_header(const char *path)
{
  HTTP_HEADER *h;
  h = g_malloc(sizeof(HTTP_HEADER));

  h->key = strdup("x-amz-copy-source");
  h->value = get_resource(path);

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
  HTTP_HEADER *h;
  char *s = time_to_s(t);
  h = g_malloc(sizeof(HTTP_HEADER));

  h->key = strdup("x-amz-meta-mtime");
  h->value = s;

  return h;
}

HTTP_HEADER *
replace_header()
{
  HTTP_HEADER *h;
  h = g_malloc(sizeof(HTTP_HEADER));

  h->key   = strdup("x-amz-metadata-directive");
  h->value = strdup("REPLACE");

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

static int
sign_request(const char *method, 
    struct curl_slist **headers, const char *path)
{
  char *signature;
  GString *to_sign;
  GString *date_header;
  GString *amz_headers;
  GString *content_type;
  GString *authorization;
  struct curl_slist *next = NULL;
  struct curl_slist *header = NULL;
  char *date = rfc2822_timestamp();
  char *resource = get_resource(path);

  amz_headers  = g_string_new("");
  content_type = g_string_new("");
  header = *headers;
  while(header != NULL) {
    next = header->next;

    if(strstr(header->data, "x-amz") != NULL) {
      amz_headers = g_string_append(amz_headers, header->data);
      amz_headers = g_string_append_c(amz_headers, '\n');
    } else if(strstr(header->data, "Content-Type") != NULL) {
      content_type = g_string_append(content_type, 
        (strstr(header->data, ":") + 1));
    }

    header = next;
  }

  content_type = g_string_append_c(content_type, '\n');
  to_sign = g_string_new("");
  to_sign = g_string_append(to_sign, method);
  to_sign = g_string_append(to_sign, "\n\n");
  to_sign = g_string_append(to_sign, content_type->str);
  to_sign = g_string_append(to_sign, date);
  to_sign = g_string_append_c(to_sign, '\n');
  to_sign = g_string_append(to_sign, amz_headers->str);
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

  g_free(date);
  g_free(resource);
  g_free(signature);
  g_string_free(to_sign, TRUE);
  g_string_free(amz_headers, TRUE);
  g_string_free(date_header, TRUE);
  g_string_free(content_type, TRUE);
  g_string_free(authorization, TRUE);

  return 0;
}

static char *
get_url(const char *path)
{
  char *url;
  GString *tmp;

  tmp = g_string_new(stormfs_curl.url);
  tmp = g_string_append(tmp, path);
  tmp = g_string_append(tmp, "?delimiter=/");
  url = strdup(tmp->str);
  g_string_free(tmp, TRUE);

  return(url);
}

static char *
get_list_bucket_url(const char *path)
{
  char *url;
  GString *tmp;

  tmp = g_string_new(stormfs_curl.url);
  tmp = g_string_append(tmp, "?delimiter=/");
  tmp = g_string_append(tmp, "&prefix=");

  if(strlen(path) > 1) {
    tmp = g_string_append(tmp, (path + 1));
    tmp = g_string_append(tmp, "/");
  }

  url = strdup(tmp->str);
  g_string_free(tmp, TRUE);

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
      value++; /* remove leading space */
      h->value = strdup(value);

      *meta = g_list_append(*meta, h);
      break;
    }

    p = strtok(NULL, "\r\n");
  }

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

  /* curl_easy_setopt(*c, CURLOPT_VERBOSE, 1L); */
  /* curl_easy_setopt(*c, CURLOPT_FORBID_REUSE, 1); */

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


static gboolean
timer_cb(gpointer data)
{
  printf("TIMER CB!\n");
  CURLMcode rc;
  struct curl_global *g = (struct curl_global *) data;

  rc = curl_multi_socket_action(g->multi,
      CURL_SOCKET_TIMEOUT, 0, &g->still_running);
  if(rc != CURLM_OK)
    printf("OMG TIMERFUCK FIXME!\n");

  return FALSE;
}

static int
update_timeout_cb(CURLM *multi, long timeout_ms, void *p)
{
  struct timeval timeout;
  struct curl_global *g = (struct curl_global *) p;

  timeout.tv_sec  = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  g->timer_event = g_timeout_add(timeout_ms, timer_cb, g);

  return 0;
}

static gboolean
event_cb(GIOChannel *io_channel, GIOCondition condition, gpointer data)
{
  printf("EVENT CB!\n");
  CURLMcode rc;
  struct curl_global *g = (struct curl_global *) data;
  int fd = g_io_channel_unix_get_fd(io_channel);

  int action = (condition & G_IO_IN ? CURL_CSELECT_IN : 0) |
      (condition & G_IO_OUT ? CURL_CSELECT_OUT : 0);

  rc = curl_multi_socket_action(g->multi, fd, action, &g->still_running);
  if(rc != CURLM_OK) {
    fprintf(stderr, "HORRIBLE EVENT FAILURE FIXME!\n");
    abort();
  }

  if(g->still_running) {
    return TRUE;
  } else {
    if(g->timer_event)
      g_source_remove(g->timer_event);

    return FALSE;
  }
}

static void
set_socket(struct curl_socket_info *f, curl_socket_t s, CURL *e, 
    int act, struct curl_global *g)
{
  printf("SET SOCKET!\n");
  GIOCondition kind = (act & CURL_POLL_IN ? G_IO_IN : 0) | 
      (act & CURL_POLL_OUT ? G_IO_OUT : 0);
  f->sockfd = s;
  f->action = act;
  f->easy = e;

  if(f->ev)
    g_source_remove(f->ev);

  f->ev = g_io_add_watch(f->io_channel, kind, event_cb, g);
}

static void
add_socket(curl_socket_t s, CURL *easy, int action, struct curl_global *g)
{
  printf("ADD SOCKET!\n");
  struct curl_socket_info *fdp = g_malloc0(sizeof(struct curl_socket_info));

  fdp->global = g;
  fdp->io_channel = g_io_channel_unix_new(s);
  set_socket(fdp, s, easy, action, g);
  curl_multi_assign(g->multi, s, fdp);
}

static void
remove_socket(struct curl_socket_info *f)
{
  if(!f)
    return;

  if(f->ev)
    g_source_remove(f->ev);

  g_free(f);
}

static void
new_connection(const char *url, struct curl_global *g)
{
  printf("NEW CONNECTION!\n");
  struct curl_connection_info *conn;
  CURLMcode rc;

  conn = g_malloc0(sizeof(struct curl_connection_info));
  conn->easy = get_curl_handle(url);
  conn->global = g;
  conn->url = url;

  // TODO: handle data returned from connection (WRITEFUNCTION, WRITEDATA)
  curl_easy_setopt(conn->easy, CURLOPT_PRIVATE, conn);
  rc = curl_multi_add_handle(g->multi, conn->easy);
  if(rc != CURLM_OK)
    printf("NEW CONNECTINO EXPLOSZIA FIXME!\n");
}

static gboolean
fifo_cb(GIOChannel *ch, GIOCondition condition, gpointer data)
{
  printf("FIFO CB!\n");
  guint BUF_SIZE = 1024;
  gsize len, t_pos;
  gchar *buf, *tmp, *all = NULL;
  GIOStatus status;

  do {
    GError *err = NULL;
    status = g_io_channel_read_line(ch, &buf, &len, &t_pos, &err);

    if(buf) {
      if(t_pos)
        buf[t_pos] = '\0';

      new_connection(buf, (struct curl_global *) data);
      g_free(buf);
    } else {
      buf = g_malloc(BUF_SIZE + 1);
      while(TRUE) {
        buf[BUF_SIZE] = '\0';
        g_io_channel_read_chars(ch, buf, BUF_SIZE, &len, &err);

        if(len) {
          buf[len] = '\0';

          if(all) {
            tmp = all;
            all = g_strdup_printf("%s%s", tmp, buf);
            g_free(tmp);
          } else {
            all = g_strdup(buf);
          }
        } else {
          break;
        }
      }

      if(all) {
        new_connection(all, (struct curl_global *) data);
        g_free(all);
      }

      g_free(buf);
    }

    if(err) {
      g_error("fifo_cb: %s", err->message);
      g_free(err);
      break;
    }
  } while((len) && (status == G_IO_STATUS_NORMAL));

  return TRUE;
}

static int
sock_cb(CURL *e, curl_socket_t s, int what, void *cbp, void *sockp)
{
  printf("SOCK CB!\n");
  struct curl_global *g = (struct curl_global *) cbp;
  struct curl_socket_info *fdp = (struct curl_socket_info *) sockp;
  static const char *whatstr[] = { "none", "IN", "OUT", "INOUT", "REMOVE" };

  printf("socket callback: s=%d e=%p what=%s ", s, e, whatstr[what]);
  if(what == CURL_POLL_REMOVE) {
    printf("\n");
    remove_socket(fdp);
  } else {
    if(!fdp) {
      printf("ADDING DATA: %s%s\n", what&CURL_POLL_IN ? "READ" : "",
                                    what&CURL_POLL_OUT ? "WRITE" : "");
      add_socket(s, e, what, g);
    } else {
      set_socket(fdp, s, e, what, g);
    }
  }

  return 0;
}

static int
set_curl_multi_defaults(CURLM **multi)
{
  printf("SET MULTI DEFAULTS!\n");
  curl_multi_setopt(*multi, CURLMOPT_SOCKETFUNCTION, sock_cb);
  curl_multi_setopt(*multi, CURLMOPT_SOCKETDATA, stormfs_curl.curl_global);
  curl_multi_setopt(*multi, CURLMOPT_TIMERFUNCTION, update_timeout_cb);
  curl_multi_setopt(*multi, CURLMOPT_TIMERDATA, stormfs_curl.curl_global);

  return 0;
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

  curl_easy_perform(c);
  result = http_response_errno(c);

  return result;
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

  curl_easy_perform(c);
  result = http_response_errno(c);

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

  curl_easy_perform(c);
  result = http_response_errno(c);
  rewind(f);

  g_free(url);
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

int
stormfs_curl_head(const char *path, GList **headers)
{
  int status;
  char *url = get_url(path);
  char *response_headers;
  CURL *c = get_curl_handle(url);
  struct curl_slist *req_headers = NULL;
  HTTP_RESPONSE data;

  data.memory = g_malloc(1);
  data.size = 0;

  sign_request("HEAD", &req_headers, path);
  curl_easy_setopt(c, CURLOPT_NOBODY, 1L);    /* HEAD */
  curl_easy_setopt(c, CURLOPT_FILETIME, 1L);  /* Last-Modified */
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, (void *) &data);
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, write_memory_cb);

  curl_easy_perform(c);
  status = http_response_errno(c);

  response_headers = strdup(data.memory);
  extract_meta(response_headers, &(*headers));

  g_free(url);
  g_free(data.memory);
  g_free(response_headers);
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return status;
}

int
stormfs_curl_list_bucket(const char *path, char **xml)
{
  int result;
  char *url = get_list_bucket_url(path);
  CURL *c = get_curl_handle(url);
  struct curl_slist *req_headers = NULL; 
  HTTP_RESPONSE body;

  body.memory = g_malloc(1);
  body.size = 0;

  sign_request("GET", &req_headers, "/");
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *) &body);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_memory_cb);

  curl_easy_perform(c);
  result = http_response_errno(c);

  *xml = strdup(body.memory);

  g_free(url);
  g_free(body.memory);
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

int
stormfs_curl_upload(const char *path, GList *headers, int fd)
{
  FILE *f;
  int status;
  char *url;
  CURL *c;
  struct stat st;
  struct curl_slist *req_headers = NULL;

  if(fstat(fd, &st) != 0)
    return -errno;

  /* TODO: support multipart uploads (>5GB files) */
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

  curl_easy_perform(c);
  status = http_response_errno(c);

  g_free(url);
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return status;
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
  curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);    /* HTTP PUT */
  curl_easy_setopt(c, CURLOPT_INFILESIZE, 0); /* Content-Length: 0 */
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *) &body);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_memory_cb);

  curl_easy_perform(c);
  result = http_response_errno(c);

  g_free(url);
  g_free(body.memory);
  destroy_curl_handle(c);
  curl_slist_free_all(req_headers);

  return result;
}

int
stormfs_curl_set_auth(const char *access_key, const char *secret_key)
{
  stormfs_curl.access_key = access_key;
  stormfs_curl.secret_key = secret_key;

  return 0;
}

void
stormfs_curl_destroy()
{
  pthread_cancel(stormfs_curl.event_thread);
  curl_global_cleanup();
  curl_multi_cleanup(stormfs_curl.curl_global->multi);
  g_io_channel_shutdown(stormfs_curl.io_channel, FALSE, NULL);
  unlink(stormfs_curl.fifo_path);
  g_free(stormfs_curl.fifo_path);
}

int
stormfs_curl_init(const char *bucket, const char *url)
{
  CURLcode result;
  GMainLoop *event_loop;
  pthread_attr_t thread_attr;
  stormfs_curl.url = url;
  stormfs_curl.bucket = bucket;
  stormfs_curl.verify_ssl = 1;
  stormfs_curl.fifo_path = g_strdup("/tmp/stormfs.fifoXXXXXX");
  stormfs_curl.fifo = init_fifo();
  stormfs_curl.io_channel = g_io_channel_unix_new(stormfs_curl.fifo);
  stormfs_curl.curl_global = g_malloc0(sizeof(struct curl_global));
  event_loop = g_main_loop_new(NULL, FALSE);

  g_io_add_watch(stormfs_curl.io_channel, G_IO_IN, fifo_cb, 
      stormfs_curl.curl_global);

  if((result = curl_global_init(CURL_GLOBAL_ALL)) != CURLE_OK)
    return -1;

  if((stormfs_curl.curl_global->multi = curl_multi_init()) == NULL)
    return -1;

  if(set_curl_multi_defaults(&stormfs_curl.curl_global->multi) != 0)
    return -1;

  // TODO: thread g_main_event_loop;
  pthread_attr_init(&thread_attr);
  pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&stormfs_curl.event_thread, &thread_attr, 
      (void *) g_main_loop_run, (void *) event_loop);

  return 0;
}
