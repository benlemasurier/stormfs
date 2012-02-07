/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef s3_curl_H
#define s3_curl_H

#define MAX_FILE_SIZE       104857600000 /* 97.65GB (10,000 * 10MB) */
#define MULTIPART_MIN       20971520  /* Minimum size for multipart files */
#define MULTIPART_CHUNK     10485760  /* 10MB */
#define MULTIPART_COPY_SIZE 524288000 /* 500MB */

typedef struct {
  int fd;
  int part_num;
  char *path;
  char *etag;
  char *upload_id;
  size_t size;
} FILE_PART;

HTTP_HEADER *acl_header(const char *acl);
HTTP_HEADER *content_header(const char *type);
HTTP_HEADER *copy_source_header(const char *path);
HTTP_HEADER *copy_source_range_header(off_t first, off_t last);
HTTP_HEADER *copy_meta_header();
HTTP_HEADER *ctime_header(time_t t);
HTTP_HEADER *expires_header(const char *expires);
HTTP_HEADER *encryption_header(void);
HTTP_HEADER *gid_header(gid_t gid);
HTTP_HEADER *mode_header(mode_t mode);
HTTP_HEADER *mtime_header(time_t t);
HTTP_HEADER *rdev_header(dev_t dev);
HTTP_HEADER *uid_header(uid_t uid);
HTTP_HEADER *replace_header();
HTTP_HEADER *storage_header(const char *class);

// FIXME: tmp non-static
FILE_PART *create_part(int part_num, char *upload_id);
char *get_resource(const char *path);
char *get_url(const char *path);
char *get_multipart_url(const char *path);
char *get_upload_part_url(const char *path, FILE_PART *fp);
char *get_complete_multipart_url(const char *path, char *upload_id);
char *get_list_bucket_url(const char *path, const char *next_marker);
char *append_list_bucket_xml(char *xml, char *xml_to_append);
char *get_etag_from_xml(char *xml);
char *get_next_marker(char *xml);
char *get_upload_id(char *xml);
bool is_truncated(char *xml);
int  sign_request(const char *method, struct curl_slist **headers, const char *path);
char *hmac_sha1(const char *key, const char *message);
struct curl_slist *headers_to_curl_slist(GList *headers);
int extract_meta(char *headers, GList **meta);
int upload_part(const char *path, FILE_PART *fp);
int copy_part(const char *from, const char *to, GList *headers, FILE_PART *fp);
char *complete_multipart_xml(GList *parts);
int complete_multipart(const char *path, char *upload_id, GList *headers, GList *parts);
char *init_multipart(const char *path, off_t size, GList *headers);
GList *create_copy_parts(const char *path, char *upload_id, off_t size);
GList *create_file_parts(const char *path, char *upload_id, int fd);
int copy_multipart(const char *from, const char *to, GList *headers, off_t size);
int upload_multipart(const char *path, GList *headers, int fd);
void free_parts(GList *parts);
void free_part(FILE_PART *fp);

int headers_to_stat(GList *headers, struct stat *stbuf);
void s3_curl_destroy(void);
int  s3_curl_delete(const char *path);
int  s3_curl_get_file(const char *path, FILE *f);
int  s3_curl_head(const char *path, GList **headers);
int  s3_curl_head_multi(const char *path, GList *files);
int  s3_curl_init(struct stormfs *stormfs);
int  s3_curl_list_bucket(const char *path, char **xml);
int  s3_curl_put(const char *path, GList *headers);
int  s3_curl_upload(const char *path, GList *headers, int fd);

#endif // s3_curl_H
