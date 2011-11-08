#ifndef stormfs_H
#define stormfs_H

static int stormfs_getattr(const char *path, struct stat *stbuf);
static int stormfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
                           off_t offset, struct fuse_file_info *fi);
static int stormfs_open(const char *path, struct fuse_file_info *fi);
static int stormfs_read(const char *path, char *buf, size_t size, off_t offset,
                        struct fuse_file_info *fi);

static int
stormfs_opt_proc(void *data, const char *arg, int key,
                 struct fuse_args *outargs);
static int stormfs_fuse_main(struct fuse_args *args);
#endif // stormfs_H
