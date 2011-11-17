#ifndef stormfs_curl_H
#define stormfs_curl_H

typedef struct {
  char *key;
  char *value;
} HTTP_HEADER;

HTTP_HEADER *gid_header(gid_t gid);
HTTP_HEADER *uid_header(uid_t uid);
HTTP_HEADER *mode_header(mode_t mode);
HTTP_HEADER *mtime_header(time_t t);
HTTP_HEADER *content_header(const char *type);
GList *strip_header(GList *headers, const char *key);
void free_headers(HTTP_HEADER *h);

int stormfs_curl_create(const char *path, uid_t uid, gid_t gid, mode_t mode, time_t mtime);
int stormfs_curl_delete(const char *path);
void stormfs_curl_destroy();
int stormfs_curl_get(const char *path, char **data);
int stormfs_curl_get_file(const char *path, FILE *f);
int stormfs_curl_head(const char *path, GList **meta);
int stormfs_curl_init(const char *bucket, const char *url);
int stormfs_curl_set_auth(const char *access_key, const char *secret_key);
int stormfs_curl_set_meta(const char *path, GList *headers);
int stormfs_curl_upload(const char *path, GList *headers, int fd);

#endif // stormfs_curl_H

