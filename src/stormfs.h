#ifndef stormfs_H
#define stormfs_H

static struct fuse_operations stormfs_oper;

static int stormfs_getattr(const char *path, struct stat *stbuf);
static int stormfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
                           off_t offset, struct fuse_file_info *fi);
static int stormfs_open(const char *path, struct fuse_file_info *fi);
static int stormfs_read(const char *path, char *buf, size_t size, off_t offset,
                        struct fuse_file_info *fi);

#endif // stormfs_H
