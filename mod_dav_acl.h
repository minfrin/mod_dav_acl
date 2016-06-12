/**
 * This is part of a mod_dav_acl library.
 *
 * Copyright (C) 2006 Nokia Corporation.
 *
 * Contact: Jari Urpalainen <jari.urpalainen@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef _MOD_DAV_ACL_H_
#define _MOD_DAV_ACL_H_

#define XML_VERSION "1.0"
#define DAV_ACL		"user.davacl"
#define DAV_OWNER	"user.owner"

#define NS_DAV		"DAV:"

#define ARRAY_SIZE(a) sizeof(a) / sizeof(a[0])
#define ARRAY(a) a,ARRAY_SIZE(a)

#define DAV_DEFAULT_PROVIDER "filesystem"

#ifdef __cplusplus
extern "C" {
#endif

DAV_DECLARE(const char *)	dav_acl_get_auth_principal(const dav_resource *resource);
DAV_DECLARE(int)		dav_acl_get_acl(const dav_resource *resource, const char **ppb, int *c);
DAV_DECLARE(void)		dav_acl_get_aggregated(const dav_resource *resource, int *acl, int *cups);

DAV_DECLARE(const char *)	dav_acl_get_principal_dir(request_rec *r);
DAV_DECLARE(const char *)	dav_acl_get_principals(request_rec *r);
DAV_DECLARE(const char *)	dav_acl_get_privs(const dav_resource *resource);
DAV_DECLARE(int)		dav_acl_is_resource_principal(const dav_resource *resource);
DAV_DECLARE(const char *)	dav_acl_get_group_membership(const dav_resource *resource);
DAV_DECLARE(const char *)	dav_acl_get_owner(const dav_resource *resource);

DAV_DECLARE(dav_error*)		dav_acl_store_owner(request_rec *r, const dav_resource *resource);

DAV_DECLARE(dav_error*)		dav_acl_check(request_rec *r, const dav_resource *resource,
					      const dav_prop_name *p, int c);

DAV_DECLARE(apr_xml_doc *)	dav_acl_get_prop_doc(request_rec *r, const xmlNode *n);

/** input filter */
typedef struct
{
    apr_bucket_brigade *pbb;
    dav_buffer buffer;
    request_rec *r;
} dav_acl_input_filter_t;

DAV_DECLARE(apr_status_t)	dav_acl_input_filter(ap_filter_t *f, apr_bucket_brigade *pbb_out, ap_input_mode_t emode, apr_read_type_e eblock, apr_off_t nbytes);

DAV_DECLARE(int)		dav_acl_read_body(request_rec *r, dav_buffer *buffer);

DAV_DECLARE(const char *)	dav_acl_get_prop(request_rec *r, const dav_resource *resource, const dav_provider *provider, const dav_prop_name *prop);

DAV_DECLARE(dav_error *)	dav_acl_privilege_error(request_rec *r, const char *pch, const char *desc, ...)
	__attribute__((__format__ (__printf__, 3, 4)));

DAV_DECLARE(int)		dav_acl_exec_error(request_rec *r, dav_error *err);

DAV_DECLARE(void)		dav_acl_last_mtime(const char *subdir, request_rec *r, apr_pool_t *pool, int recur);

#ifdef __cplusplus
}
#endif

#endif /* _MOD_DAV_ACL_H_ */

