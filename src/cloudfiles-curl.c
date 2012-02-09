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
#include "cloudfiles-curl.h"

#define RACKSPACE_US_AUTH_URL "https://auth.api.rackspacecloud.com/v1.0"
#define RACKSPACE_UK_AUTH_URL "https://lon.auth.api.rackspacecloud.com/v1.0"

struct cloudfiles_curl {
  char *auth_token;
  char *storage_url;
  struct stormfs *stormfs;
} cf_curl;

enum auth_endpoint
{
  AUTH_US,
  AUTH_UK
};

char *
auth_url(enum auth_endpoint endpoint)
{
  switch(endpoint) {
    case AUTH_US:
          return strdup(RACKSPACE_US_AUTH_URL);
    case AUTH_UK:
          return strdup(RACKSPACE_UK_AUTH_URL);
  }

  return strdup(RACKSPACE_US_AUTH_URL);
}

char *
cloudfiles_url(const char *path)
{
  char *url;
  char *encoded_path = url_encode((char *) path);

  if(asprintf(&url, "%s/%s%s", 
        cf_curl.storage_url, cf_curl.stormfs->bucket, encoded_path) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }

  free(encoded_path);

  return url;
}

char *
list_objects_url(const char *path)
{
  char *url;
  char *encoded_path = url_encode((char *) path);

  /*
  if(asprintf(&url, "%s/%s?format=json&delimiter=/&path=%s", 
        cf_curl.storage_url, cf_curl.stormfs->bucket, encoded_path) == -1) {
        */
  if(asprintf(&url, "%s/%s?delimiter=/", 
        cf_curl.storage_url, cf_curl.stormfs->bucket) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }

  free(encoded_path);

  return url;
}

HTTP_HEADER *
auth_user_header(const char *username)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);
  h->key = strdup("X-Auth-User");
  h->value = strdup(username);

  return h;
}

HTTP_HEADER *
auth_key_header(const char *key)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);
  h->key = strdup("X-Auth-Key");
  h->value = strdup(key);

  return h;
}

HTTP_HEADER *
auth_token_header(const char *token)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);
  h->key = strdup("X-Auth-Token");
  h->value = strdup(token);

  return h;
}

HTTP_REQUEST *
cloudfiles_request(const char *path)
{
  HTTP_REQUEST *request = new_request(path);
  request->url = cloudfiles_url(path);
  request->c = get_pooled_handle(request->url);

  return request;
}

static char *
extract_header_value(const char *haystack, const char *needle)
{
  char *p, *value = NULL;
  char *tmp = strdup(haystack);

  p = strtok(tmp, "\r\n");
  while(p != NULL) {
    if(!strstr(p, needle)) {
      p = strtok(NULL, "\r\n");
      continue;
    }

    /* remove leading space */
    value = strstr(p, " ");
    value++;

    value = strdup(value);
    break;

    p = strtok(NULL, "\r\n");
  }

  free(tmp);

  return value;
}

static int
extract_meta(char *headers, GList **meta)
{
  char *p;
  char *to_extract[10] = {
    "Content-Type",
    "Content-Length",
    "Last-Modified",
    "Etag",
    "X-Object-Meta-Gid",
    "X-Object-Meta-Uid",
    "X-Object-Meta-Rdev",
    "X-Object-Meta-Mode",
    "X-Object-Meta-Ctime",
    "X-Object-Meta-Mtime"
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

      h = malloc(sizeof(HTTP_HEADER));
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

static struct curl_slist *
headers_to_curl_slist(GList *headers)
{
  GList *head = NULL, *next = NULL;
  struct curl_slist *curl_headers = NULL;

  head = g_list_first(headers);
  while(head != NULL) {
    next = head->next;
    HTTP_HEADER *h = head->data;

    char *s = header_to_s(h);
    if(strstr(h->key, "X-Auth-") != NULL)
      curl_headers = curl_slist_append(curl_headers, s);
    else if(strstr(h->key, "X-Object-Meta") != NULL)
      curl_headers = curl_slist_append(curl_headers, s);
    else if(strstr(h->key, "Expires") != NULL)
      curl_headers = curl_slist_append(curl_headers, s);
    else if(strstr(h->key, "Content-Type") != NULL)
      curl_headers = curl_slist_append(curl_headers, s);
    free(s);

    head = next;
  }

  return curl_headers;
}

static int
cloudfiles_curl_authenticate(void)
{
  int result;
  GList *headers = NULL;
  HTTP_REQUEST *request = new_request("/");

  headers = add_header(headers, auth_user_header(cf_curl.stormfs->username));
  headers = add_header(headers, auth_key_header(cf_curl.stormfs->access_key));

  request->url = auth_url(AUTH_US);
  request->c = get_pooled_handle(request->url);
  request->headers = headers_to_curl_slist(headers);

  if((result = stormfs_curl_get_headers(request)) == 0) {
    cf_curl.auth_token = extract_header_value(request->response.memory, 
        "X-Auth-Token:");
    cf_curl.storage_url = extract_header_value(request->response.memory, 
        "X-Storage-Url");
  }

  free_headers(headers);
  free_request(request);

  return result;
}

int
cloudfiles_curl_init(struct stormfs *stormfs)
{
  int result;

  cf_curl.stormfs = stormfs;
  if((result = stormfs_curl_init(stormfs)) != 0)
    return result;

  return cloudfiles_curl_authenticate();
}

int
cloudfiles_curl_head(const char *path, GList **headers)
{
  int result;
  HTTP_REQUEST *request = cloudfiles_request(path);

  *headers = add_header(*headers, auth_token_header(cf_curl.auth_token));
  request->headers = headers_to_curl_slist(*headers);

  result = stormfs_curl_head(request);

  extract_meta(request->response.memory, headers);
  free_request(request);

  return result;
}

int
cloudfiles_curl_head_multi(const char *path, GList *files)
{
  /* FIXME: s3_curl and cloudfiles_curl are duplicating this
   * function, abstract out to main curl interface */
  int running_handles;
  size_t i, n_running, last_req_idx = 0;
  size_t n_files = g_list_length(files);
  HTTP_REQUEST *requests = g_new0(HTTP_REQUEST, n_files);
  GList *head = NULL, *next = NULL, *headers = NULL;
  CURLM *multi = get_multi_handle();
  headers = add_header(headers, auth_token_header(cf_curl.auth_token));

  i = 0;
  n_running = 0;
  head = g_list_first(files);
  while(head != NULL) {
    next = head->next;
    struct file *f = head->data;

    CURLMcode err;
    requests[i].headers = headers_to_curl_slist(headers);
    requests[i].response.memory = g_malloc0(1);
    requests[i].response.size = 0;
    requests[i].path = get_path(path, f->name);
    requests[i].done = false;

    if(n_running < MAX_REQUESTS && n_running < n_files) {
      char *url = cloudfiles_url(requests[i].path);
      requests[i].c = get_pooled_handle(url);
      curl_easy_setopt(requests[i].c, CURLOPT_NOBODY, 1L);   // HEAD
      curl_easy_setopt(requests[i].c, CURLOPT_FILETIME, 1L); // Last-Modified
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
      free(requests[i].response.memory);
      curl_slist_free_all(requests[i].headers);
      curl_multi_remove_handle(multi, requests[i].c);
      release_pooled_handle(requests[i].c);
      requests[i].done = true;
      n_running--;

      if(n_running < MAX_REQUESTS && last_req_idx < (n_files - 1)) {
        CURLMcode err;
        last_req_idx++;;

        char *url = cloudfiles_url(requests[last_req_idx].path);
        requests[last_req_idx].c = get_pooled_handle(url);
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
    free(requests[i].path);
  }
  free(requests);

  return 0;
}

int
cloudfiles_curl_list_objects(const char *path, char **data)
{
  int result;
  GList *headers = NULL;
  HTTP_REQUEST *request = new_request(path);

  headers = add_header(headers, auth_token_header(cf_curl.auth_token));

  request->url = list_objects_url(path);
  request->c = get_pooled_handle(request->url);
  request->headers = headers_to_curl_slist(headers);

  if((result = stormfs_curl_get(request)) == 0)
    *data = strdup(request->response.memory);

  free_headers(headers);
  free_request(request);

  return result;
}
