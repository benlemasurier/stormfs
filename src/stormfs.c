/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#define FUSE_USE_VERSION 26

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>

#include "stormfs.h"

static int
stormfs_getattr(const char *path, struct stat *stbuf)
{
  return -ENOENT;
}

static int
stormfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
                           off_t offset, struct fuse_file_info *fi)
{
  return -ENOENT;
}

static int
stormfs_open(const char *path, struct fuse_file_info *fi)
{
  return -ENOENT;
}

static int
stormfs_read(const char *path, char *buf, size_t size, off_t offset,
                        struct fuse_file_info *fi)
{
  return -ENOENT;
}

int
main(int argc, char *argv[])
{
  // map FUSE bindings
  memset(&stormfs_oper, 0, sizeof(stormfs_oper));
  stormfs_oper.getattr = stormfs_getattr;
  stormfs_oper.readdir = stormfs_readdir;
  stormfs_oper.open    = stormfs_open;
  stormfs_oper.read    = stormfs_read;

  // hand off control to FUSE
  return fuse_main(argc, argv, &stormfs_oper, NULL);
}
