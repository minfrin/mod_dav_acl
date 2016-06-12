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

#ifndef _DAV_PRIVATE_H_
#define _DAV_PRIVATE_H_

#define NS_DAV  "DAV:"

#define DBHOOKS(conf)  (conf && conf->provider) ? conf->provider->propdb : NULL

#define ARRAY_SIZE(a) sizeof(a) / sizeof(a[0])
#define ARRAY(a) a,ARRAY_SIZE(a)

#define FOR_CHILD(node, parent) \
	for (node = parent ? parent->children : NULL; node; node = node->next)

#define NODE_NS(node) (node->ns && node->ns->href && \
			strcmp((char *) node->ns->href, NS_DAV) == 0)

#define NODE_NOT_DAV(node) node->type != XML_ELEMENT_NODE || !NODE_NS(node)

#define NODE_MATCH(node, y) (strcmp((char *) node->name, y) == 0)

/* directory configuration data */
typedef struct _davacl_dir_cfg {
    char *shared_mem_file;		/* shared mem file name */
    char *principals;			/* http://example.com/principals */
    char *principal_dir;		/* local directory for principals */

    int shared_mem;			/* shared memory max size for
					 * principals */
    unsigned owner_full_rights:1,	/* owner has full rights if not any
					 * acl is set */
	     use_std_property_db:1,	/* store acl as standard dead
					 * property */
	     acl_aggregated:1,		/* acl aggregated into read */
	     cups_aggregated:1;		/* current-user-privilege-set aggregated
					 * into read privilege */

    apr_shm_t *shm;			/* shared memory segment */
    apr_rmm_t *rmm;			/* rmm pool within shm */

    apr_rmm_off_t *off_user;		/* first user record offset in the
					 * shared memory area */
    apr_pool_t *pool;			/* pool */

    const dav_provider *provider;	/* filesystem provider */

} davacl_dir_cfg;

/* server configuration data */
typedef struct _davacl_server_cfg {
    char *lock_file;			/* mutex lock file name */
    apr_global_mutex_t *mutex;		/* global mutex for shared memory */
} davacl_server_cfg;

int acl_get_acl(const dav_resource *resource, const davacl_dir_cfg *conf,
                const char *filename, const char **ppb, int *c);

const char *acl_get_principal_uri(request_rec *r, const davacl_dir_cfg *conf);
const char *acl_get_owner(const dav_resource *resource,
                          const davacl_dir_cfg *conf, const char *filename);

const char *acl_get_group(const dav_resource *resource,
                          const davacl_dir_cfg *conf);


static inline void acl_lock(davacl_server_cfg *sconf)
{
    if (sconf && sconf->mutex)
	apr_global_mutex_lock(sconf->mutex);
}

static inline void acl_unlock(davacl_server_cfg *sconf)
{
    if (sconf && sconf->mutex)
	apr_global_mutex_unlock(sconf->mutex);
}


#define ADDRESS(conf, off)		apr_rmm_addr_get(conf->rmm, off)
#define UID(conf, off)			(acl_uid_t *) (ADDRESS(conf, off))
#define USERNAME(conf, off)		(char *) (ADDRESS(conf, off))
#define GET_USERNAME(conf, off)		off ? USERNAME(conf, off) : NULL

/* principal object structure in shared memory */
typedef struct
{
    apr_rmm_off_t next,		/* next struct pointer */
		  user,		/* principal uri */
		  displayname,	/* displayname */
		  children;	/* group member list */
} acl_uid_t;

#define LOOP_MAX 20

#if DEBUG
    #define TRACE(r, arg...) \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, ##arg)
    #define TRACE_WARNING(r, arg...) \
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, ##arg)
    #define TRACE_ERROR(r, arg...) \
	ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server, ##arg)
#else
     #define TRACE(r, arg...) do {} while (0)
     #define TRACE_WARNING(r, arg...) do {} while (0)
     #define TRACE_ERROR(r, arg...) do {} while (0)
#endif

dav_error *acl_check_req(request_rec *r, const char *filename,
                         const dav_resource *resource,
                         const davacl_dir_cfg *conf,
                         const dav_prop_name *name, int count, int count_loop);

const char *acl_get_principal_dir(const davacl_dir_cfg *conf);

int acl_is_user_group_member(const char *user, const char *group,
                             const davacl_dir_cfg *conf);

void acl_store_owner(request_rec *r, const dav_resource *resource,
                     davacl_dir_cfg *conf);

void acl_update_principal(request_rec *r, const dav_resource *resource,
                          davacl_dir_cfg *conf);

void acl_update_all_principals(request_rec *r, davacl_dir_cfg *conf);

void acl_shm_init(const request_rec *r, davacl_dir_cfg *conf);

dav_error *acl_store_acl(request_rec *r, dav_resource *resource,
                         davacl_dir_cfg *conf, dav_buffer *buffer);

#define REPOS(conf) (conf && conf->provider) ? conf->provider->repos : NULL

#define MAX_RECURSION 10

#endif /* _DAV_PRIVATE_H_ */

