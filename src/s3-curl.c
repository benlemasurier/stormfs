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
#include "s3-curl.h"

#define SHA1_BLOCK_SIZE 64
#define SHA1_LENGTH     20
#define MAX_REQUESTS    100

struct s3_curl {
  const char *access_key;
  const char *secret_key;
  struct stormfs *stormfs;
} s3_curl;

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
copy_source_range_header(off_t first, off_t last)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-copy-source-range");
  if(asprintf(&h->value, "bytes=%jd-%jd", 
        (intmax_t) first, (intmax_t) last) == -1)
    fprintf(stderr, "unable to allocate memory\n");

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
encryption_header(void)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-server-side-encryption");
  h->value = strdup("AES256");

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
rdev_header(dev_t rdev)
{
  char *s = rdev_to_s(rdev);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("x-amz-meta-rdev");
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

char *
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

FILE_PART *
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

int
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

char *
get_etag_from_xml(char *xml)
{
  char *tmp, *etag;
  char *start_marker = "ETag>&quot;";
  char *end_marker  = "&quot;</ETag";
  char *start_p, *end_p;

  start_p = strstr(xml, start_marker) + strlen(start_marker);
  end_p   = strstr(xml, end_marker);

  tmp = g_strndup(start_p, end_p - start_p);
  if(asprintf(&etag, "\"%s\"", tmp) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }

  free(tmp);
  return etag;
}


char *
get_next_marker(char *xml)
{
  char *start_marker = "NextMarker>";
  char *end_marker  = "</NextMarker";
  char *start_p, *end_p;

  start_p = strstr(xml, start_marker) + strlen(start_marker);
  end_p   = strstr(xml, end_marker);

  return g_strndup(start_p, end_p - start_p);
}

char *
get_resource(const char *path)
{
  int path_len = strlen(path);
  int bucket_len = strlen(s3_curl.stormfs->bucket);
  char *resource = g_malloc0(sizeof(char) * path_len + bucket_len + 2);

  strncpy(resource, "/", 1);
  strncat(resource, s3_curl.stormfs->bucket, bucket_len);
  strncat(resource, path, path_len);

  return resource;
}

char *
get_upload_id(char *xml)
{
  char *start_marker = "UploadId>";
  char *end_marker  = "</UploadId";
  char *start_p, *end_p;

  start_p = strstr(xml, start_marker) + strlen(start_marker);
  end_p   = strstr(xml, end_marker);

  return g_strndup(start_p, end_p - start_p);
}

char *
get_url(const char *path)
{
  char *url;
  char *encoded_path = url_encode((char *) path);

  if(asprintf(&url, "%s%s?delimiter=/", s3_curl.stormfs->virtual_url, encoded_path) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }
  free(encoded_path);

  return url;
}

char *
get_multipart_url(const char *path)
{
  char *url;
  char *encoded_path = url_encode((char *) path);

  if(asprintf(&url, "%s%s?uploads", s3_curl.stormfs->virtual_url, encoded_path) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }
  free(encoded_path);

  return url;
}

char *
get_upload_part_url(const char *path, FILE_PART *fp)
{
  char *url;
  char *encoded_path = url_encode((char *) path);

  if(asprintf(&url, "%s%s?partNumber=%d&uploadId=%s",
      s3_curl.stormfs->virtual_url, encoded_path, fp->part_num, fp->upload_id) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }
  free(encoded_path);

  return url;
}

char *
get_complete_multipart_url(const char *path, char *upload_id)
{
  char *url;
  char *encoded_path = url_encode((char *) path);

  if(asprintf(&url, "%s%s?uploadId=%s",
      s3_curl.stormfs->virtual_url, encoded_path, upload_id) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }
  free(encoded_path);

  return url;
}

char *
get_list_bucket_url(const char *path, const char *next_marker)
{
  int result;
  char *url;
  char *encoded_path = url_encode((char *) path);

  if(strlen(path) > 1)
    result = asprintf(&url, "%s?delimiter=/&marker=%s&prefix=%s/",
        s3_curl.stormfs->virtual_url, next_marker, encoded_path + 1);
  else
    result = asprintf(&url, "%s?delimiter=/&marker=%s&prefix=",
        s3_curl.stormfs->virtual_url, next_marker);

  if(result == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }

  free(encoded_path);

  return url;
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

int
headers_to_stat(GList *headers, struct stat *stbuf)
{
  GList *head = NULL,
        *next = NULL;

  head = g_list_first(headers);
  while(head != NULL) {
    next = head->next;
    HTTP_HEADER *header = head->data;

    // TODO: clean this up.
    if(strcmp(header->key, "x-amz-meta-uid") == 0)
      stbuf->st_uid = get_uid(header->value);
    else if(strcmp(header->key, "x-amz-meta-gid") == 0)
      stbuf->st_gid = get_gid(header->value);
    else if(strcmp(header->key, "x-amz-meta-ctime") == 0)
      stbuf->st_ctime = get_ctime(header->value);
    else if(strcmp(header->key, "x-amz-meta-mtime") == 0)
      stbuf->st_mtime = get_mtime(header->value);
    else if(strcmp(header->key, "x-amz-meta-rdev") == 0)
      stbuf->st_rdev = get_rdev(header->value);
    else if(strcmp(header->key, "Last-Modified") == 0 && stbuf->st_mtime == 0)
      stbuf->st_mtime = get_mtime(header->value);
    else if(strcmp(header->key, "x-amz-meta-mode") == 0)
      stbuf->st_mode = get_mode(header->value);
    else if(strcmp(header->key, "Content-Length") == 0)
      stbuf->st_size = get_size(header->value);
    else if(strcmp(header->key, "Content-Type") == 0)
      if(strstr(header->value, "x-directory"))
        stbuf->st_mode |= S_IFDIR;

    head = next;
  }

  return 0;
}

char *
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

bool
is_truncated(char *xml)
{
  if(strstr(xml, "<IsTruncated>true"))
    return true;

  return false;
}

int
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

  if(asprintf(&to_sign, "%s\n\n%s\n%s\n%s%s",
      method, content_type, date, amz_headers, resource) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }

  signature = hmac_sha1(s3_curl.secret_key, to_sign);

  if(asprintf(&authorization, "Authorization: AWS %s:%s",
      s3_curl.access_key, signature) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }

  if(asprintf(&date_header, "Date: %s", date) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }
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

int
s3_curl_init(struct stormfs *stormfs)
{
  s3_curl.stormfs = stormfs;
  s3_curl.access_key = stormfs->access_key;
  s3_curl.secret_key = stormfs->secret_key;

  return stormfs_curl_init(stormfs);
}

void
s3_curl_destroy(void)
{
  stormfs_curl_destroy();
}

int
s3_curl_list_bucket(const char *path, char **xml)
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

int
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

  if(asprintf(&sign_path, "%s?partNumber=%d&uploadId=%s",
      path, fp->part_num, fp->upload_id) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }

  sign_request("PUT", &req_headers, sign_path);
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

int
copy_part(const char *from, const char *to, GList *headers, FILE_PART *fp)
{
  int result;
  CURL *c;
  char *url;
  char *sign_path;
  HTTP_RESPONSE response;
  struct curl_slist *req_headers = NULL;
  GList *response_headers = NULL, *stripped_headers = NULL;

  response.memory = malloc(1);
  response.size = 0;
  url = get_upload_part_url(to, fp);
  c = get_pooled_handle(url);

  if(asprintf(&sign_path, "%s?partNumber=%d&uploadId=%s",
      to, fp->part_num, fp->upload_id) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }

  headers = g_list_first(headers);
  stripped_headers = g_list_copy(headers);
  stripped_headers = strip_header(stripped_headers, "x-amz-meta");
  req_headers = headers_to_curl_slist(stripped_headers);

  sign_request("PUT", &req_headers, sign_path);
  curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(c, CURLOPT_INFILESIZE, 0);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, req_headers);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *) &response);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_memory_cb);
  result = stormfs_curl_easy_perform(c);

  fp->etag = get_etag_from_xml(response.memory);

  free(url);
  free(sign_path);
  free(response.memory);
  free_headers(response_headers);
  curl_slist_free_all(req_headers);
  release_pooled_handle(c);

  return result;
}

char *
complete_multipart_xml(GList *parts)
{
  int result;
  GList *head = NULL, *next = NULL;
  char *xml = strdup("<CompleteMultipartUpload>\n");

  xml = realloc(xml, sizeof(char) *
      strlen(xml) + (g_list_length(parts) * 150));

  head = g_list_first(parts);
  while(head != NULL) {
    next = head->next;
    FILE_PART *fp = head->data;
    char *part_xml;

    result = asprintf(&part_xml, "  <Part>\n"
                                 "    <PartNumber>%d</PartNumber>\n"
                                 "    <ETag>%s</ETag>\n"
                                 "  </Part>\n",
        fp->part_num, fp->etag);
    if(result == -1) {
      fprintf(stderr, "unable to allocate memory\n");
      exit(EXIT_FAILURE);
    }
    xml = strncat(xml, part_xml, strlen(part_xml));

    free(part_xml);
    head = next;
  }

  xml = g_realloc(xml, strlen(xml) + 27);
  xml = strcat(xml, "</CompleteMultipartUpload>\n");

  return xml;
}

int
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

  if(asprintf(&sign_path, "%s?uploadId=%s", path, upload_id) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }

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

char *
init_multipart(const char *path, off_t size, GList *headers)
{
  int result;
  CURL *c;
  char *url;
  char *sign_path;
  char *upload_id = NULL;
  HTTP_RESPONSE body;
  struct curl_slist *req_headers = NULL;

  body.memory = g_malloc(1);
  body.size = 0;

  if(asprintf(&sign_path, "%s?uploads", path) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }

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

GList *
create_copy_parts(const char *path, char *upload_id, off_t size)
{
  int part_num = 1;
  off_t bytes_remaining;
  GList *parts = NULL;

  bytes_remaining = size;
  while(bytes_remaining > 0) {
    FILE_PART *fp = create_part(part_num, upload_id);

    fp->path = strdup(path);
    if(bytes_remaining > MULTIPART_COPY_SIZE)
      fp->size = MULTIPART_COPY_SIZE;
    else
      fp->size = bytes_remaining;

    parts = g_list_append(parts, fp);
    part_num++;
    bytes_remaining = bytes_remaining - fp->size;
  }

  return parts;
}

GList *
create_file_parts(const char *path, char *upload_id, int fd)
{
  FILE *f;
  struct stat st;
  size_t bytes_remaining;
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

int
copy_multipart(const char *from, const char *to, GList *headers, off_t size)
{
  int result;
  char *upload_id = NULL;
  GList *parts = NULL, *head = NULL, *next = NULL;

  if((upload_id = init_multipart(to, size, headers)) == NULL)
    return -EIO;

  if((parts = create_copy_parts(to, upload_id, size)) == NULL)
    return -EIO;

  off_t bytes_written = 0;
  head = g_list_first(parts);
  while(head != NULL) {
    next = head->next;
    FILE_PART *fp = head->data;
    off_t first = bytes_written;
    off_t last = bytes_written + (fp->size - 1);
    headers = add_header(headers, copy_meta_header());
    headers = add_header(headers, copy_source_header(from));
    headers = add_header(headers, copy_source_range_header(first, last));

    if((result = copy_part(from, to, headers, fp)) != 0)
      break;

    bytes_written = last + 1;
    head = next;
  }

  result = complete_multipart(to, upload_id, headers, parts);
  free_parts(parts);

  return result;
}

int
upload_multipart(const char *path, GList *headers, int fd)
{
  int result = 0;
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

void
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
  g_list_foreach(parts, (GFunc) free_part, NULL);
  g_list_free(parts);
}

int
s3_curl_head_multi(const char *path, GList *files)
{
  int running_handles;
  size_t i, n_running, last_req_idx = 0;
  size_t n_files = g_list_length(files);
  HTTP_REQUEST *requests = g_new0(HTTP_REQUEST, n_files);
  GList *head = NULL, *next = NULL;
  CURLM *multi = get_multi_handle();

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

      if((err = curl_multi_add_handle(multi, requests[i].c)) != CURLM_OK)
        return -EIO;

      n_running++;
      last_req_idx = i;
    }

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
        // requests *might* share the same handle out of the pool,
        // make sure the request hasn't also been marked as completed
        if(msg->easy_handle == requests[i].c && !requests[i].done)
          break;
      }

      struct file *f = g_list_nth_data(files, i);
      extract_meta(requests[i].response.memory, &(f->headers));
      g_free(requests[i].response.memory);
      curl_slist_free_all(requests[i].headers);
      curl_multi_remove_handle(multi, requests[i].c);
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

        if((err = curl_multi_add_handle(multi, requests[last_req_idx].c)) != CURLM_OK)
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
s3_curl_delete(const char *path)
{
  int result;
  HTTP_REQUEST *request = new_request(path);
  sign_request("DELETE", &request->headers, request->path);

  result = stormfs_curl_delete(request);

  free_request(request);
  return result;
}

int
s3_curl_get_file(const char *path, FILE *f)
{
  int result;
  HTTP_REQUEST *request = new_request(path);

  sign_request("GET", &request->headers, path);
  result = stormfs_curl_get_file(request, f);
  free_request(request);

  return result;
}

int
s3_curl_head(const char *path, GList **headers)
{
  int result;
  HTTP_REQUEST *request = new_request(path);

  request->headers = headers_to_curl_slist(*headers);
  sign_request("HEAD", &request->headers, request->path);

  result = stormfs_curl_head(request);

  extract_meta(request->response.memory, headers);
  free_request(request);

  return result;
}

int
s3_curl_put(const char *path, GList *headers)
{
  int result;
  HTTP_REQUEST *request = new_request(path);

  request->headers = headers_to_curl_slist(headers);
  sign_request("PUT", &request->headers, request->path);

  result = stormfs_curl_put(request);
  free_request(request);

  return result;
}

int
s3_curl_upload(const char *path, GList *headers, int fd)
{
  int result;
  FILE *f;
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
  request->size = st.st_size;
  request->headers = headers_to_curl_slist(headers);
  sign_request("PUT", &request->headers, request->path);

  curl_easy_setopt(request->c, CURLOPT_INFILE, f);

  result = stormfs_curl_put(request);
  free_request(request);

  return result;
}
