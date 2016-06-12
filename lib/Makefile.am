#
# A DAV ACL module.
#
# Copyright (C) 2006 Nokia Corporation.
#
# Contact: Jari Urpalainen <jari.urpalainen@nokia.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

# $Id:$

# ----------------------------------------------------------------------
# General options

lib_LTLIBRARIES = libdavacl.la

# Define the source file for the module library
libdavacl_la_SOURCES = dav_acl.c

# Define that an include directory is required.
libdavacl_la_CFLAGS = $(APACHE_INC) $(DEPS_MOD_CFLAGS)

libdavacl_la_LIBADD = $(DEPS_MOD_LIBS)
