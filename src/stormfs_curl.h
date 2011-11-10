#ifndef stormfs_curl_H
#define stormfs_curl_H

int stormfs_curl_init(const char *bucket, const char *url);
int stormfs_curl_set_auth(const char *access_key, const char *secret_key);
int stormfs_curl_get(const char *path);
void stormfs_curl_destroy();

#endif // stormfs_curl_H

