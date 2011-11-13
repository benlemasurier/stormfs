/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include <stdio.h>
#include <string.h>

char *
ltrim(char *s)
{
  while((*s == ' ') || (*s == '\t'))
    s++;

  return s;
}
