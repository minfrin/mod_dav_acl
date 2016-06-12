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

SUBDIRS = lib tools man

lib_LTLIBRARIES = mod_dav_acl.la

# Define the source file for the module
mod_dav_acl_la_SOURCES = mod_dav_acl.c acl_liveprops.c

# Define that an include directory is required.
mod_dav_acl_la_CFLAGS = $(APACHE_INC) $(DEPS_MOD_CFLAGS)

# this is dlopened
mod_dav_acl_la_LDFLAGS = -avoid-version -module

mod_dav_acl_la_LIBADD = $(DEPS_MOD_LIBS) $(top_builddir)/lib/libdavacl.la

davacldir=$(sysconfdir)/$(APACHE_CONFIG_DIR)
davacl_DATA = dav_acl.conf dav_acl.load

pkgconfigdir = @libdir@/pkgconfig
pkgconfig_DATA = mod_dav_acl.pc

mod_dav_acl_includedir = $(includedir)/$(APACHE_INCLUDE_DIR)
mod_dav_acl_include_HEADERS = mod_dav_acl.h

libdir = @libdir@/$(APACHE_MODULE_DIR)

TESTS = acl_tests
noinst_SCRIPTS = acl_tests

test: check
