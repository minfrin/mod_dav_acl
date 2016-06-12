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

#if 0
LoadModule dav_acl_module modules/mod_davacl.so

<Location /principals>
   Dav on

   AuthType Digest
   AuthName "testing"
   AuthUserFile /var/www/passwords
   Require valid-user
   AuthDigestProvider file

   FileETag MTime NanoSecsMTime

   DAVETagResponse on
   DAVACL on

   AclOwnerFullRights on
   AclLockFile      /var/tmp/davacl.lock
   AclSharedMemFile /var/tmp/davacl.shm
   AclSharedMemSize 16000
   AclPrincipals    http://example.com/principals
   AclPrincipalDir  /jfs/principals
   AclUsePropertyDB on
   AclAggregatedCurrentUserPrivilegeSet on
   AclAggregatedAcl off

</Location>

#endif

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "http_core.h"

#include "apr_shm.h"
#include "apr_rmm.h"
#include "apr_strings.h"
#include "apr_global_mutex.h"

#undef PACKAGE_NAME
#undef PACKAGE_VERSION
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME

#include "config.h"

#include "mod_dav.h"

#include "unixd.h"

#include <libxml/tree.h>

#include "mod_dav_acl.h"
#include "acl_liveprops.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>

#include "acl_private.h"

module AP_MODULE_DECLARE_DATA dav_acl_module[];

/* ACL METHOD index */
static int iM_ACL, iM_HEAD;

#define ACL_FILTER "acl_filter_in"


static dav_error *check_acl(request_rec *r, const dav_resource *resource,
				davacl_dir_cfg *conf,
				const dav_hooks_repository *repos)
{
    dav_error *err = NULL;
    const dav_prop_name privs[] = {
	{ NS_DAV, "write" },
	{ NS_DAV, "write-acl" } };

    /* Note: depth == 0. Implies no need for a multistatus response. */
    if ((err = dav_validate_request(r, (dav_resource *) resource, 0,
				    NULL, NULL, DAV_VALIDATE_RESOURCE,
				    NULL)) != NULL) {
	/* ### add a higher-level description? */
	return dav_new_error(r->pool, err->status, 0, err->desc);
    }

    return acl_check_req(r, r->filename, resource, conf, ARRAY(privs), 0);
}

static dav_error *parent_check(request_rec *r, const dav_resource *resource,
				davacl_dir_cfg *conf,
				const dav_hooks_repository *repos,
				const dav_prop_name *privs, int count)
{
    dav_resource *parent = NULL;
    dav_error *err = NULL;

    if ((err = repos->get_parent_resource(resource, &parent)))
	return err;

    return acl_check_req(r, repos->get_pathname(parent), parent, conf, privs,
								count, 0);
}

static dav_error *check_put(request_rec *r, const dav_resource *resource,
				davacl_dir_cfg *conf,
				const dav_hooks_repository *repos)
{
    if (resource->exists) {
	const dav_prop_name privs[] = {
		{ NS_DAV, "write" },
		{ NS_DAV, "write-content" } };

	return acl_check_req(r, r->filename, resource, conf, ARRAY(privs), 0);
    }
    else {
	const dav_prop_name privs[] = {
		{ NS_DAV, "write" },
		{ NS_DAV, "bind" } };

	return parent_check(r, resource, conf, repos, ARRAY(privs));
    }
}

static dav_error *check_proppatch(request_rec *r, const dav_resource *resource,
					davacl_dir_cfg *conf,
					const dav_hooks_repository *repos)
{
    const dav_prop_name privs[] = {
	{ NS_DAV, "write" },
	{ NS_DAV, "write-properties" } };

    return acl_check_req(r, r->filename, resource, conf, ARRAY(privs), 0);
}

static dav_error *check_get(request_rec *r, const dav_resource *resource,
				davacl_dir_cfg *conf,
				const dav_hooks_repository *repos)
{
    const dav_prop_name privs[] = { { NS_DAV, "read" } };

    return acl_check_req(r, r->filename, resource, conf, ARRAY(privs), 0);
}

static dav_error *check_mkcol(request_rec *r, const dav_resource *resource,
				davacl_dir_cfg *conf,
				const dav_hooks_repository *repos)
{
    const dav_prop_name privs[] = {
	{ NS_DAV, "write" },
	{ NS_DAV, "bind" } };

    return parent_check(r, resource, conf, repos, ARRAY(privs));
}

static dav_error *check_delete(request_rec *r, const dav_resource *resource,
				davacl_dir_cfg *conf,
				const dav_hooks_repository *repos)
{
    const dav_prop_name privs[] = { { NS_DAV, "write" }, { NS_DAV, "unbind" } };

    /* this is more liberal than rfc3744, i.e. the write privilege on a
     * resource will allow delete to happen */
    if (acl_check_req(r, r->filename, resource, conf, privs, 1, 0) == NULL)
	return NULL;

    return parent_check(r, resource, conf, repos, privs + 1, 1);
}

static dav_error *check_copy(request_rec *r, const dav_resource *resource,
				davacl_dir_cfg *conf,
				const dav_hooks_repository *repos)
{
    if (r->main == NULL) { /* source */
	const dav_prop_name privs[] = { { NS_DAV, "read" } };

	return acl_check_req(r, r->filename, resource, conf, ARRAY(privs), 0);
    }
    else { /* destination */
	const dav_prop_name privs[] = {
		{ NS_DAV, "write-content" },	/* 0 */
		{ NS_DAV, "write-properties" },	/* 1 */
		{ NS_DAV, "write" },		/* 2 */
		{ NS_DAV, "bind" } };		/* 3 */

	if (resource->exists) {
	    dav_error *err = acl_check_req(r, r->filename,
					   resource, conf, privs + 2, 1, 0);

	    if (err == NULL)
		return NULL;
	    else if (acl_check_req(r, r->filename, resource,
				   conf, privs, 1, 0) == NULL &&
		     acl_check_req(r, r->filename, resource,
				   conf, privs + 1, 1, 0) == NULL)
		return NULL;

	    return err;
	}
	else {
	    return parent_check(r, resource, conf, repos, privs + 2, 2);
	}
    }
}

static dav_error *check_move(request_rec *r, const dav_resource *resource,
				davacl_dir_cfg *conf,
				const dav_hooks_repository *repos)
{
    if (r->main == NULL) { /* source */
	const dav_prop_name privs[] = { { NS_DAV, "write" },
					{ NS_DAV, "unbind" } };

	if (acl_check_req(r, r->filename, resource, conf, privs, 1, 0) == NULL)
	    return NULL;

	return parent_check(r, resource, conf, repos, ARRAY (privs));
    }
    else { /* destination */
	const dav_prop_name privs[] = {
		{ NS_DAV, "write" },			/* 0 */
		{ NS_DAV, "write-content" },		/* 1 */
		{ NS_DAV, "write-properties" },		/* 2 */
		{ NS_DAV, "unbind" },			/* 3 */
		{ NS_DAV, "write" },			/* 4 */
		{ NS_DAV, "bind" } };			/* 5 */

	if (resource->exists) {
	    dav_error *err = NULL;

	    if (acl_check_req(r, r->filename, resource, conf, privs, 1, 0) == NULL)
		return NULL;
	    else if (acl_check_req(r, r->filename, resource, conf,
					privs + 1, 1, 0) == NULL &&
			acl_check_req(r, r->filename, resource, conf,
					privs + 2, 1, 0) == NULL)
		return NULL;

	    err = parent_check(r, resource, conf, repos, privs + 3, 2);
	    if (err)
		return err;
	}

	return parent_check(r, resource, conf, repos, privs + 4, 2);
    }
}

static dav_error *check_lock(request_rec *r, const dav_resource *resource,
                             davacl_dir_cfg *conf,
                             const dav_hooks_repository *repos)
{
    if (resource->exists) {
	const dav_prop_name privs[] = {
		{ NS_DAV, "write" },
		{ NS_DAV, "write-content" } };

	return acl_check_req(r, r->filename, resource, conf, ARRAY(privs), 0);
    }
    else {
	const dav_prop_name privs[] = {
		{ NS_DAV, "write" },
		{ NS_DAV, "bind" } };

	return parent_check(r, resource, conf, repos, ARRAY(privs));
    }
}

static dav_error *check_unlock(request_rec *r, const dav_resource *resource,
                               davacl_dir_cfg *conf,
                               const dav_hooks_repository *repos)
{
    const dav_prop_name privs[] = { { NS_DAV, "unlock" } };

    return acl_check_req(r, r->filename, resource, conf, ARRAY(privs), 0);
}

/**
 * generic acl checking for different methods (basic set of methods supported)
 * returns null if no err
 */
static dav_error *check_methods(request_rec *r, const dav_resource *resource,
                                davacl_dir_cfg *conf)
{
    const dav_hooks_repository *repos = REPOS(conf);

    if (repos == NULL || resource == NULL)
	return dav_acl_privilege_error(r, "unknown", NULL);

    switch (r->method_number) {
    default:
	if (r->method_number == iM_ACL) {
	    return check_acl(r, resource, conf, repos);
	}
	else if (r->method_number == iM_HEAD) {
	    return check_get(r, resource, conf, repos);
	}
	else {
	    TRACE(r, "Unknown methdod:%d", r->method_number);
	    return NULL;
	}
	break;

    case M_PUT:
	return check_put(r, resource, conf, repos);

    case M_PROPPATCH:
	return check_proppatch(r, resource, conf, repos);

    case M_MKCOL:
	return check_mkcol(r, resource, conf, repos);

    case M_PROPFIND:
	/* done with individual properties within dav_get_props() and
	 * dav_get_allprops */
	return NULL;

    case M_DELETE:
	return check_delete(r, resource, conf, repos);

    case M_OPTIONS:
    case M_GET:
	return check_get(r, resource, conf, repos);

    case M_COPY:
	return check_copy(r, resource, conf, repos);

    case M_MOVE:
	return check_move(r, resource, conf, repos);

    case M_LOCK:
	return check_lock(r, resource, conf, repos);

    case M_UNLOCK:
	return check_unlock(r, resource, conf, repos);
    }
}

static void principal(request_rec *r, const dav_resource *resource,
                      const davacl_dir_cfg *conf, xmlNode * child,
                      apr_hash_t *base)
{
    xmlNode * uri;
    const char *pch;

    FOR_CHILD(uri, child) {
	if (NODE_NOT_DAV(uri)) {
	    ;
	}
	else if (NODE_MATCH(uri, "href")) {
	    xmlChar *href = xmlNodeGetContent(uri);

	    if (href) {
		pch = apr_pstrdup(r->pool, (char *) href);
		apr_hash_set(base, pch, APR_HASH_KEY_STRING, pch);
		xmlFree(href);
	    }
	}
	else if (NODE_MATCH(uri, "property")) {
	    xmlNode * prop;

	    FOR_CHILD(prop, uri) {
		pch = NULL;

		if (NODE_NOT_DAV(prop))
		    ;
		else if (NODE_MATCH(prop, "owner"))
		    pch = acl_get_owner(resource, conf, r->filename);
		else if (NODE_MATCH(prop, "group"))
		    pch = acl_get_group(resource, conf);

		if (pch)
		    apr_hash_set(base, pch, APR_HASH_KEY_STRING, pch);
	    }
	}
    }
}

/** locate principal uris from acl */
static dav_error *find_principals(request_rec *r, const dav_resource *resource,
                                  const davacl_dir_cfg *conf,
                                  apr_hash_t **pbase)
{
    xmlDoc *doc;
    xmlNode *node;
    apr_hash_t *base;
    const char *pch;
    int rc, size;

    rc = acl_get_acl(resource, conf, r->filename, &pch, &size);
    if (rc < 0)
	return dav_new_error(r->pool, HTTP_NOT_FOUND, 0,
		apr_psprintf(r->pool, "No ACL found for the resource %s.",
				      ap_escape_html(r->pool, r->uri)));

    doc = xmlParseMemory(pch, size);
    node = doc ? doc->children : NULL;
    base = apr_hash_make(r->pool);

    for ( ; node; node = node->next) {
	xmlNode *ace, *child;

	if (NODE_NOT_DAV(node) || NODE_MATCH(node, "acl") == FALSE)
	    continue;

	FOR_CHILD(ace, node) {
	    if (NODE_NOT_DAV(ace) || NODE_MATCH(ace, "ace") == FALSE)
		continue;

	    FOR_CHILD(child, ace) {
		if (NODE_NOT_DAV(child))
		    ;
		else if (NODE_MATCH(child, "principal"))
		    principal(r, resource, conf, child, base);
	    }
	}
    }
    xmlFreeDoc(doc);
    *pbase = base;

    return NULL;
}

/** set acl for a resource */
static dav_error *acl_set(request_rec *r, dav_resource *resource,
                          davacl_dir_cfg *conf)
{
    dav_buffer buffer[1] = { { 0 } };

    if (dav_acl_read_body(r, buffer) < 0)
	return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
			     "Message's request body could not be read");

    return acl_store_acl(r, resource, conf, buffer);
}

/* server config create */
static void *create_server_config(apr_pool_t *p, server_rec *s)
{
    return apr_pcalloc(p, sizeof(davacl_server_cfg));
}

/* global lock filename */
static const char *cmd_lock_file(cmd_parms *cmd, void *mconfig, const char *pch)
{
    server_rec *s = cmd->server;
    davacl_server_cfg *
	conf = ap_get_module_config(s->module_config, dav_acl_module);

    conf->lock_file = apr_psprintf(cmd->pool, "%s", pch ? pch :
				   "/var/tmp/davacl.lock");

    return NULL;
}

static void *create_dir_config(apr_pool_t *p, char *dirspec)
{
    davacl_dir_cfg *conf = apr_pcalloc(p, sizeof(*conf));
    conf->pool = p;

#if !HAVE_XATTR
    conf->use_std_property_db = TRUE;
#endif

    return conf;
}

/* directive */
static const char *cmd_shared_mem_file(cmd_parms *cmd, void *mconfig,
					const char *pch)
{
    davacl_dir_cfg *conf = mconfig;

    conf->shared_mem_file = apr_psprintf(cmd->pool, "%s",
					 pch ? pch : "/var/tmp/davacl.shm");

    return NULL;
}

/* directive */
static const char *cmd_shared_mem_size(cmd_parms *cmd, void *mconfig,
					const char *pch)
{
    davacl_dir_cfg *conf = mconfig;

    conf->shared_mem = pch ? atoi(pch) : 65000;

    if (conf->shared_mem < sizeof(apr_rmm_off_t))
	conf->shared_mem = sizeof(apr_rmm_off_t) + 500;

    return NULL;
}

/* directive */
static const char *cmd_owner_full_rights(cmd_parms *cmd, void *mconfig, int arg)
{
    davacl_dir_cfg *conf = mconfig;

    conf->owner_full_rights = arg;

    return NULL;
}

/* directive */
static const char *cmd_acl_aggregated(cmd_parms *cmd, void *mconfig, int arg)
{
    davacl_dir_cfg *conf = mconfig;

    conf->acl_aggregated = arg;

    return NULL;
}

/* directive */
static const char *cmd_cups_aggregated(cmd_parms *cmd, void *mconfig, int arg)
{
    davacl_dir_cfg *conf = mconfig;

    conf->cups_aggregated = arg;

    return NULL;
}

/* directive */
static const char *cmd_use_property_db(cmd_parms *cmd, void *mconfig, int arg)
{
    davacl_dir_cfg *conf = mconfig;

#if HAVE_XATTR
    conf->use_std_property_db = arg;
#else
    conf->use_std_property_db = TRUE;
#endif

    return NULL;
}

/* directive */
static const char *cmd_principal_dir(cmd_parms *cmd, void *mconfig,
                                     const char *pch)
{
    davacl_dir_cfg *conf = mconfig;

    conf->principal_dir = apr_psprintf(cmd->pool, "%s",
				       pch ? pch : "/var/www/principals");
    if (pch == NULL)
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		     "mod_dav_acl: directory for principals not given "
		     "(anticipating %s)", conf->principal_dir);

    return NULL;
}

/* directive */
static const char *cmd_principal_host_path(cmd_parms *cmd, void *mconfig,
                                           const char *pch)
{
    davacl_dir_cfg *conf = mconfig;

    if (pch == NULL) {
	char sz[200] = "";

	if (gethostname(sz, sizeof(sz) - 1) != 0)
	    strcpy(sz, "localhost");

	conf->principals = apr_psprintf(cmd->pool, "http://%s/principals", sz);

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		     "mod_dav_acl: principal base uri not given "
		     "(anticipating %s)", conf->principals);
    }
    else {
	conf->principals = apr_psprintf(cmd->pool, "%s", pch);
    }

    return NULL;
}

/* cmd callbacks */
static const command_rec dav_acl_cmds[] =
{
    AP_INIT_TAKE1(
	"AclLockFile",			/* directive name */
	cmd_lock_file,			/* config action routine */
	NULL,				/* argument to include in call */
	OR_OPTIONS,			/* where available */
	"lock file name"		/* directive description */
      ),
    AP_INIT_TAKE1(
	"AclSharedMemFile",		/* directive name */
	cmd_shared_mem_file,		/* config action routine */
	NULL,				/* argument to include in call */
	OR_OPTIONS,			/* where available */
	"shared mem file name"		/* directive description */
      ),
    AP_INIT_TAKE1(
	"AclSharedMemSize",		/* directive name */
	cmd_shared_mem_size,		/* config action routine */
	NULL,				/* argument to include in call */
	OR_OPTIONS,			/* where available */
	"Shared mem size for user identities"
					/* directive description */
      ),
    AP_INIT_FLAG(
	"AclOwnerFullRights",		/* directive name */
	cmd_owner_full_rights,		/* config action routine */
	NULL,				/* argument to include in call */
	OR_OPTIONS,			/* where available */
	"Only owner has full rights if no acl is set"
					/* directive description */
      ),
    AP_INIT_FLAG(
	"AclUsePropertyDB",		/* directive name */
	cmd_use_property_db,		/* config action routine */
	NULL,				/* argument to include in call */
	OR_OPTIONS,			/* where available */
	"Standard property db used for ACLs"
					/* directive description */
      ),
    AP_INIT_TAKE1(
	"AclPrincipals",		/* directive name */
	cmd_principal_host_path,	/* config action routine */
	NULL,				/* argument to include in call */
	OR_OPTIONS,			/* where available */
	"Base URI for principals (http://example.com/principals)"
					/* directive description */
      ),
    AP_INIT_TAKE1(
	"AclPrincipalDir",		/* directive name */
	cmd_principal_dir,		/* config action routine */
	NULL,				/* argument to include in call */
	OR_OPTIONS,			/* where available */
	"Local real directory for principals (/var/www/principals)"
					/* directive description */
      ),
    AP_INIT_FLAG(
	"AclAggregatedCurrentUserPrivilegeSet",	/* directive name */
	cmd_cups_aggregated,		/* config action routine */
	NULL,				/* argument to include in call */
	OR_OPTIONS,			/* where available */
	"current-user-privilege-set aggregated into 'read' privilege"
					/* directive description */
      ),
    AP_INIT_FLAG(
	"AclAggregatedAcl",		/* directive name */
	cmd_acl_aggregated,		/* config action routine */
	NULL,				/* argument to include in call */
	OR_OPTIONS,			/* where available */
	"ACLs reading aggregated into 'read' privilege"
					/* directive description */
      ),
    {NULL}
};

static inline void init_acl(request_rec *r, davacl_server_cfg **sconf,
                            davacl_dir_cfg **conf)
{
    *sconf = ap_get_module_config(r->server->module_config, dav_acl_module);
    *conf = ap_get_module_config(r->per_dir_config, dav_acl_module);

    acl_lock(*sconf);

    if (*conf && (*conf)->shm == NULL)
	acl_shm_init(r, *conf);
}

/** check acl for a method */
static dav_error *check_method(request_rec *r, const dav_resource *resource)
{
    dav_error *err;
    davacl_server_cfg *sconf;
    davacl_dir_cfg *conf;

    init_acl(r, &sconf, &conf);
    err = check_methods(r, resource, conf);
    acl_unlock(sconf);

    return err;
}

/** check read privilege */
static dav_error *check_read_common(davacl_dir_cfg *conf, request_rec *r,
                                    const dav_resource *resource)
{
    const dav_prop_name privs[] = { { NS_DAV, "read" } };
    const dav_hooks_repository *repos = REPOS(conf);
    const char *filename = repos ? repos->get_pathname(resource) : NULL;

    return acl_check_req(r, filename, resource, conf, ARRAY(privs), 0);
}

/** check prop name privilege */
DAV_DECLARE (dav_error *) dav_acl_check(request_rec *r,
                                        const dav_resource *resource,
                                        const dav_prop_name *privs, int c)
{
    dav_error *err;
    const char *filename;
    davacl_server_cfg *sconf;
    davacl_dir_cfg *conf;
    const dav_hooks_repository *repos;

    init_acl(r, &sconf, &conf);
    repos = REPOS(conf);
    filename = repos ? repos->get_pathname(resource) : NULL;
    err = acl_check_req(r, filename, resource, conf, privs, c, 0);
    acl_unlock(sconf);

    return err;
}

/** check read privilege with locks */
static dav_error *check_read(request_rec *r, const dav_resource *resource)
{
    dav_error *err;
    davacl_server_cfg *sconf;
    davacl_dir_cfg *conf;

    init_acl(r, &sconf, &conf);
    err = check_read_common(conf, r, resource);
    acl_unlock(sconf);

    return err;
}

/** check read privilege without locks */
static dav_error *check_read_nolock(request_rec *r,
                                    const dav_resource *resource)
{
    davacl_dir_cfg *conf;

    conf = ap_get_module_config(r->per_dir_config, dav_acl_module);

    return check_read_common(conf, r, resource);
}

/** check prop privilege */
static dav_error *check_prop_common(davacl_dir_cfg *conf, request_rec *r,
                                    const dav_resource *resource,
                                    const dav_prop_name *name,
                                    dav_prop_insert what)
{
    dav_prop_name privs[] = { { NS_DAV, "read-acl" } };
    const char *filename;
    const dav_hooks_repository *repos;

    if (name->ns == NULL || strcmp(name->ns, NS_DAV)) {
	return NULL;
    }
    else {
	int acl = strcmp(name->name, "acl") == 0,
	    cups = strcmp(name->name, "current-user-privilege-set") == 0;

	if ((!acl && !cups) || (conf->acl_aggregated && acl) ||
		(conf->cups_aggregated && cups))
	    return NULL;

	if (cups)
	    privs->name = "read-current-user-privilege-set";
    }

    /* only acl or current-user-privilege-set tested */
    repos = REPOS(conf);
    filename = repos ? repos->get_pathname(resource) : NULL;

    return acl_check_req(r, filename, resource, conf, ARRAY(privs), 0);
}

/** prop privilege without locks */
static dav_error *check_prop_nolock(request_rec *r,
                                    const dav_resource *resource,
                                    const dav_prop_name *name,
                                    dav_prop_insert what)
{
    davacl_dir_cfg *conf;

    conf = ap_get_module_config(r->per_dir_config, dav_acl_module);

    return check_prop_common(conf, r, resource, name, what);
}

/**
 * prop privilege with locks for special properties
 * only "acl" and "current-user-privilege-set" are checked
 */
static dav_error *check_prop(request_rec *r, const dav_resource *resource,
                             const dav_prop_name *name, dav_prop_insert what)
{
    dav_error *err;
    davacl_server_cfg *sconf;
    davacl_dir_cfg *conf;

    init_acl(r, &sconf, &conf);
    err = check_prop_common(conf, r, resource, name, what);
    acl_unlock(sconf);

    return err;
}

/** proppatch could be optimized as group_member_set is being tracked */
static void post_processing(request_rec *r, const dav_resource *resource,
                            int fstore_owner)
{
    const char *pch;
    davacl_server_cfg *sconf;
    davacl_dir_cfg *conf;
    const dav_hooks_propdb *db_hooks;

    if (r == NULL || resource == NULL || r->user == NULL)
	return;

    init_acl(r, &sconf, &conf);
    db_hooks = DBHOOKS(conf);

    if (db_hooks == NULL || conf->principals == NULL) {
	acl_unlock(sconf);
	return;
    }

    /* successful put, mkcol or e.g. mkcalendar,
     * i.e. store the owner of a resource */
    if (fstore_owner)
	acl_store_owner(r, resource, conf);

    /* principal update ? */
    pch = acl_get_principal_dir(conf);
    if (pch && strncmp(pch, r->filename, strlen(pch)) == 0) {
	if ((r->method_number == M_PUT &&
				(r->status == 201 || r->status == 204)) ||
	    (r->method_number == M_PROPPATCH &&
				(r->status == 207 || r->status == 200)))
	    acl_update_principal(r, resource, conf);
	else if (r->method_number != M_MKCOL &&
		  r->method_number != M_PUT &&
		  r->method_number != M_PROPPATCH)
	    /* FULL update of principals */
	    acl_update_all_principals(r, conf);
    }

    acl_unlock(sconf);
}

/** acl hooks */
static dav_hooks_acl acl =
{
    check_method,
    check_read,
    check_prop,
    post_processing,
    NULL
};

static dav_hooks_acl *acl_nolock(void)
{
    static dav_hooks_acl nolock =
    {
	acl_check_read: check_read_nolock,
	acl_check_prop: check_prop_nolock,
	0
    };
    return &nolock;
}

/** principal property search report */
static int dump_principal_search_property_set(request_rec *r)
{
    xmlNs *ns;
    xmlNode *child, *node;
    xmlChar *pch;
    int cb;
    xmlDoc * doc = xmlNewDoc((const xmlChar *) XML_VERSION);

    child = doc->children = xmlNewDocNode(doc, NULL,
			(const xmlChar *) "principal-search-property-set", NULL);
    xmlSetNs(child, ns = xmlNewNs(child, (const xmlChar *) NS_DAV,
			     (const xmlChar *) "D"));
    node = xmlNewChild(child, ns,
			(const xmlChar *) "principal-search-property", NULL);
    child = xmlNewChild(node, ns, (const xmlChar *) "prop", NULL);
    xmlNewChild(child, ns, (const xmlChar *) "displayname", NULL);
    child = xmlNewChild(node, ns, (const xmlChar *) "description",
			(const xmlChar *) "Full name");
    xmlSetProp(child, (const xmlChar *) "xml:lang", (const xmlChar *) "en");
    xmlDocDumpFormatMemoryEnc(doc, &pch, &cb, "UTF-8", 1);

    ap_set_content_type(r, "application/xml");
    ap_rprintf(r, "%.*s", cb, pch);

    xmlFree(pch);
    xmlFreeDoc(doc);
    r->status_line = ap_get_status_line(r->status);

    return DONE;
}

/** send generic props */
static void send_props(apr_bucket_brigade *bb, request_rec *r, request_rec *rf,
                       dav_resource *resource, apr_pool_t *subpool,
                       xmlNode * node_prop)
{
    dav_response response[1] = { { 0 } };
    dav_propdb *propdb = NULL;

    rf->user = r->user;
    rf->per_dir_config = r->per_dir_config;
    rf->server = r->server;

    response->href = rf->uri;

    if (node_prop) {
	apr_xml_doc *adoc = dav_acl_get_prop_doc(r, node_prop);

	dav_open_propdb(rf, NULL, resource, 1, adoc->namespaces, &propdb);
	if (propdb)
	    response->propresult = dav_get_props(propdb, adoc);
    }

    apr_pool_clear(subpool);

    dav_send_one_response(response, bb, r->output_filters, subpool);

    if (propdb)
	dav_close_propdb(propdb);
}

/** init multistatus response */
static void init_multistatus(apr_bucket_brigade **bb, request_rec *r)
{
    if (*bb)
	return;

    *bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    dav_begin_multistatus(*bb, r, HTTP_MULTI_STATUS, NULL);
}

/** send principal props */
static void send_principal_props(const char *uri, apr_bucket_brigade **bb,
                                 request_rec *r, davacl_dir_cfg *conf,
                                 apr_pool_t *subpool, xmlNode * node_prop)
{
    dav_resource *resource = NULL;
    dav_error *err = NULL;
    request_rec *rf;
    const dav_hooks_repository *repos = REPOS(conf);

    if (conf->principal_dir == NULL || conf->principals == NULL ||
		repos == NULL)
	return;

    rf = apr_pcalloc(subpool, sizeof(*rf));
    rf->user = r->user;
    rf->uri = apr_psprintf(rf->pool = subpool, "%s", uri);
    rf->filename = apr_psprintf(rf->pool, "%s%s", conf->principal_dir,
				rf->uri + strlen(conf->principals));
    apr_stat(&rf->finfo, rf->filename, APR_FINFO_MIN, rf->pool);
    err = repos->get_resource(rf, NULL, NULL, 0, &resource);

    if (err == NULL) {
	resource->acl_hooks = acl_nolock();

	/* don't report principal if no read privilege exists */
	if (check_read_common(conf, rf, resource) == NULL) {
	    init_multistatus(bb, r);

	    send_props(*bb, r, rf, resource, subpool, node_prop);
	}
    }
}

/** principal property set report */
static int dump_principal_prop_set(dav_resource *resource, request_rec *r,
                                   davacl_dir_cfg *conf, xmlNode * node)
{
    apr_hash_t *base = NULL;
    apr_hash_index_t *hi;
    dav_error *err;
    apr_pool_t *subpool;
    apr_bucket_brigade *bb = NULL;

    if ((err = find_principals(r, resource, conf, &base)))
	return dav_acl_exec_error(r, err);

    FOR_CHILD(node, node) {
	if (NODE_NOT_DAV(node))
	    ;
	else if (NODE_MATCH(node, "prop"))
	    break;
    }
    apr_pool_create(&subpool, r->pool);

    for (hi = apr_hash_first(r->pool, base); hi; hi = apr_hash_next(hi)) {
	const void *key;
	void *val;

	apr_hash_this(hi, &key, NULL, &val);

	send_principal_props(val, &bb, r, conf, subpool, node);
    }
    apr_pool_destroy(subpool);

    if (bb)
	dav_finish_multistatus(r, bb);
    else
	r->status_line = ap_get_status_line(r->status = 404);

    return DONE;
}

/** principal property search report */
static int dump_principal_property_search(request_rec *r, davacl_dir_cfg *conf,
                                          xmlNode *node, const char *puri)
{
    apr_rmm_off_t off;
    acl_uid_t *aud;
    xmlNode *n, *prop, *value;
    apr_pool_t *subpool;
    apr_bucket_brigade *bb = NULL;

    apr_pool_create(&subpool, r->pool);

    for (off = *conf->off_user; off; off = aud->next) {
	const char *display_name, *user;
	xmlChar *display_value = NULL;
	int f = -1;

	aud = UID(conf, off);
	display_name = GET_USERNAME(conf, aud->displayname);
	user = GET_USERNAME(conf, aud->user);

	if (user == NULL || strncmp(user, puri, strlen(puri)) != 0)
	    continue;

	FOR_CHILD(n, node) {
	    if (NODE_NOT_DAV(n)) {
		;
	    }
	    else if (NODE_MATCH(n, "property-search")) {
		FOR_CHILD(prop, n) {
		    if (NODE_NOT_DAV(prop)) {
			;
		    }
		    else if (NODE_MATCH(prop, "prop")) {
			FOR_CHILD(value, prop) {
			    if (NODE_NOT_DAV(value)) {
				if (value->type == XML_ELEMENT_NODE)
				    f = FALSE;
			    }
			    else if (NODE_MATCH(value, "displayname") == FALSE) {
				f = FALSE;
			    }
			    else if (NODE_MATCH(value, "displayname") && f < 0) {
				f = TRUE;
			    }
			}
		    }
		    else if (NODE_MATCH(prop, "match")) {
			display_value = xmlNodeGetContent(prop);
		    }
		}
	    }
	}

	if (f > 0 && display_value && display_name &&
		xmlStrcasestr((xmlChar *) display_name, display_value)) {

	    FOR_CHILD(n, node) {
		if (NODE_NOT_DAV(n) || NODE_MATCH(n, "prop") == FALSE)
		    continue;

		send_principal_props(USERNAME(conf, aud->user), &bb, r,
				     conf, subpool, n);
		break;
	    }
	}
	xmlFree(display_value);
    }
    apr_pool_destroy(subpool);

    if (bb)
	dav_finish_multistatus(r, bb);
    else
	r->status_line = ap_get_status_line(r->status = 404);

    return DONE;
}

/** sending multipart owner props */
static void send_owner_props(const char *subdir, const char *user,
                             apr_bucket_brigade *bb, request_rec *r,
                             davacl_dir_cfg *conf, apr_pool_t *subpool,
                             xmlNode * node, int recur)
{
    const char *dir = subdir ? subdir : r->filename;
    DIR *dp = opendir(dir);
    const dav_hooks_repository *repos = REPOS(conf);
    struct dirent *res = NULL;
    struct dirent entry[offsetof(struct dirent, d_name) +
				 pathconf(dir, _PC_NAME_MAX) + 1];

    for ( ; repos && readdir_r(dp, entry, &res) == 0 && res != NULL; ) {
	char *file;
	struct stat st = { 0 };

	/* no current/parent dir or hidden file == .* */
	if (entry->d_name[0] == '.')
	    continue;

	file = apr_pstrcat(subpool, dir, "/", entry->d_name, NULL);
	if (stat(file, &st) != 0)
	    continue;

	if ((st.st_mode & S_IFDIR) == S_IFDIR && recur < MAX_RECURSION) {
	    send_owner_props(file, user, bb, r, conf, subpool, node, ++recur);
	}
	else if ((st.st_mode & S_IFREG) == S_IFREG) {
	    dav_resource *resource = NULL;
	    dav_error *err;
	    const char *owner;
	    request_rec *rf = apr_pcalloc(subpool, sizeof(*rf));

	    rf->filename = file;
	    rf->uri = apr_pstrcat(rf->pool = subpool, r->uri,
				  file + strlen(r->filename), NULL);
	    apr_stat(&rf->finfo, rf->filename, APR_FINFO_MIN, rf->pool);
	    err = repos->get_resource(rf, NULL, NULL, 0, &resource);
	    if (err)
		continue;

	    owner = acl_get_owner(resource, conf, file);

	    if (owner && user && strcmp(user, owner) == 0)
		send_props(bb, r, rf, resource, subpool, node);
	}
    }
    closedir(dp);
}

/** principal match report */
static int dump_principal_match(request_rec *r, davacl_dir_cfg *conf,
                                xmlNode *parent)
{
    xmlNode *n, *prop, *node = NULL;
    int f = -1;
    apr_pool_t *subpool;
    apr_bucket_brigade *bb = NULL;

    FOR_CHILD(n, parent) {
	if (NODE_NOT_DAV(n)) {
	    ;
	}
	else if (NODE_MATCH(n, "self")) {
	    f = 0;
	}
	else if (NODE_MATCH(n, "principal-property")) {
	    FOR_CHILD(prop, n) {
		if (NODE_MATCH(prop, "owner"))
		    f = 1;
		else
		    f = -1;
	    }
	}
	else if (NODE_MATCH(n, "prop")) {
	    node = n;
	}
	else {
	    f = -1;
	}
    }

    if (f < 0)
	return dav_acl_exec_error(r, dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
				  "Given REPORT not supported, only self & owner"));

    if (f == 0) {
	const char *pch = acl_get_principal_dir(conf);

	if (pch && strncmp(pch, r->filename, strlen(pch)))
	    return dav_acl_exec_error(r, dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
				      "Wrong R-URI in principal (<self>) REPORT"));
    }
    else {
	DIR *dp = opendir(r->filename);

	if (dp == NULL)
	    return dav_acl_exec_error(r, dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
				      "A collection URI is required by REPORT"));
	closedir(dp);
    }

    apr_pool_create(&subpool, r->pool);

    if (f == 0) {
	const char *user = acl_get_principal_uri(r, conf);
	acl_uid_t *aud;
	apr_rmm_off_t off;

	for (off = *conf->off_user; user && off; off = aud->next) {
	    const char *pch;

	    aud = UID(conf, off);
	    pch = GET_USERNAME(conf, aud->user);

	    if ((pch && strcmp(pch, user) == 0) ||
			(aud->children &&
			 acl_is_user_group_member(user, pch, conf)))
		send_principal_props(pch, &bb, r, conf, subpool, node);
	}
    }
    else {
	const char *user = acl_get_principal_uri(r, conf);

	if (user) {
	    init_multistatus(&bb, r);
	    send_owner_props(NULL, user, bb, r, conf, subpool, node, 0);
	}
    }

    apr_pool_destroy(subpool);

    if (bb)
	dav_finish_multistatus(r, bb);
    else
	r->status_line = ap_get_status_line(r->status = 404);

    return DONE;
}

static int acl_method(request_rec *r, davacl_server_cfg *sconf,
                      davacl_dir_cfg *conf, const dav_hooks_repository *repos)
{
    dav_resource *resource = NULL;
    dav_error *err;
    const char *pch;
    int size, rc;

    if ((err = repos->get_resource(r, NULL, NULL, 0, &resource)))
	return dav_acl_exec_error(r, err);

    rc = acl_get_acl(resource, conf, r->filename, &pch, &size);
    r->status = rc > 0 ? 200 : 201;

    if ((err = check_methods(r, resource, conf)) == NULL)
	err = acl_set(r, resource, conf);

    if (err)
	return dav_acl_exec_error(r, err);

    r->status_line = ap_get_status_line(r->status);
    ap_set_content_type(r, "text/html");
    ap_rprintf(r, "ACL was successfully set");

    return DONE;
}

static int report_method(request_rec *r, davacl_server_cfg *sconf,
                         davacl_dir_cfg *conf,
                         const dav_hooks_repository *repos)
{
    dav_resource *resource = NULL;
    dav_error *err = NULL;
    xmlDoc * doc = NULL;
    ap_filter_t *inf;
    dav_buffer *buffer = NULL;
    int rc = 0;
    const char *pch, *puri;
    xmlNode * node;

    pch = acl_get_principal_dir(conf);
    if (pch == NULL || strncmp(pch, r->filename, strlen(pch)) != 0) {
	TRACE(r, "principals:%s request:%s", pch ? pch : "none", r->filename);
	return DECLINED;
    }

    if ((err = repos->get_resource(r, NULL, NULL, 0, &resource)))
	return dav_acl_exec_error(r, err);

    if (resource->collection == FALSE)
	return dav_acl_exec_error(r, dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
				  "R-URI must be a collection URI"));

    puri = apr_psprintf(r->pool, "%s%s", conf->principals,
			r->filename + strlen(pch));

    /* read the body content from the input filter buffer if it was consumed
     * already by another client */
    for (inf = r->input_filters; inf; inf = inf->next) {
	if (inf->frec && inf->frec->name &&
		strcmp(inf->frec->name, ACL_FILTER) == 0) {
	    dav_acl_input_filter_t *f = inf->ctx;

	    if (f && f->r == r) {
		inf->ctx = NULL;
		buffer = &f->buffer;
		ap_remove_input_filter(inf);
		break;
	    }
	}
    }
    if (buffer == NULL) {  /* internal error actually */
	ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server,
		     "mod_dav_acl: input filter failed");
	return DECLINED;
    }

    if (buffer->cur_len == 0)
	rc = dav_acl_read_body(r, buffer);

    if (rc < 0 ||
	(doc = xmlReadMemory(buffer->buf, buffer->cur_len,
			     NULL, NULL, XML_PARSE_NOWARNING)) == NULL)
	return DECLINED;

    for (node = doc->children; node; node = node->next) {
	if (NODE_NOT_DAV(node)) {
	    if (node->type == XML_ELEMENT_NODE) {
		xmlFreeDoc(doc);
		return DECLINED;
	    }
	}
	else if (NODE_MATCH(node, "acl-principal-prop-set")) {
	    if (dav_get_depth(r, 0) != 0)
		goto error;

	    acl_lock(sconf);
	    dump_principal_prop_set(resource, r, conf, node);
	    acl_unlock(sconf);
	    break;
	}
	else if (NODE_MATCH(node, "principal-match")) {
	    if (dav_get_depth(r, 0) != 0)
		goto error;

	    acl_lock(sconf);
	    dump_principal_match(r, conf, node);
	    acl_unlock(sconf);
	    break;
	}
	else if (NODE_MATCH(node, "principal-property-search")) {
	    if (dav_get_depth(r, 0) != 0)
		goto error;

	    acl_lock(sconf);
	    dump_principal_property_search(r, conf, node, puri);
	    acl_unlock(sconf);
	    break;
	}
	else if (NODE_MATCH(node, "principal-search-property-set")) {
	    dump_principal_search_property_set(r);
	    break;
	}
	else if (node->type == XML_ELEMENT_NODE) {
	    xmlFreeDoc(doc);
	    return DECLINED;
	}
    }
    xmlFreeDoc(doc);

    return OK;

error:
    xmlFreeDoc(doc);
    err = dav_new_error(r->pool, HTTP_BAD_REQUEST,
			0, "Depth-header value incorrect");

    return dav_acl_exec_error(r, err);
}

/* davacl handler callback */
static int davacl_handler(request_rec *r)
{
    davacl_server_cfg *sconf;
    davacl_dir_cfg *conf;
    const char *name;
    const dav_hooks_repository *repos;

    /* dav enabled ? */
    name = dav_get_provider_name(r);
    if (name == NULL || strcmp(name, DAV_DEFAULT_PROVIDER) != 0)
	return DECLINED;

    init_acl(r, &sconf, &conf);
    acl_unlock(sconf);

    if ((repos = REPOS(conf)) == NULL)
	return DECLINED;

    if (r->method_number == iM_ACL)
	return acl_method(r, sconf, conf, repos);
    else if (r->method_number == M_REPORT)
	return report_method(r, sconf, conf, repos);

    return DECLINED;
}

/** child spawnup */
static void initialize_child(apr_pool_t *pool, server_rec *s)
{
    davacl_server_cfg *conf;
    apr_status_t rc;

    conf = ap_get_module_config(s->module_config, dav_acl_module);
    if (conf == NULL)
	return;

    rc = apr_global_mutex_child_init(&conf->mutex, conf->lock_file, pool);
    if (rc != APR_SUCCESS)
	ap_log_error(APLOG_MARK, APLOG_CRIT, rc, s,
		     "mod_dav_acl: could not init child");
}

/** global mutex cleanup */
static apr_status_t cleanup_mutex(void *user_data)
{
    davacl_server_cfg *conf = user_data;

    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
		 "mod_dav_acl: cleaning up shared memory");
    if (conf) {
	apr_global_mutex_destroy(conf->mutex);
	conf->mutex = NULL;
    }

    return APR_SUCCESS;
}

/** module init */
static int initialize_module(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                             server_rec *s)
{
    void *data;
    apr_status_t rc;
    const char *key = "davacl_start";
    davacl_server_cfg *sconf;

    /* initialize_acl_module(), will be called twice, and if it's a DSO
     * then all static data from the first call will be lost. Only
     * set up our static data on the second call. */
    apr_pool_userdata_get(&data, key, s->process->pool);
    if (data == NULL) {
	apr_pool_userdata_set((const void *) 1, key,
			      apr_pool_cleanup_null, s->process->pool);
	return OK;
    }

    sconf = ap_get_module_config(s->module_config, dav_acl_module);

    rc = apr_global_mutex_create(&sconf->mutex, sconf->lock_file,
				 APR_LOCK_DEFAULT, p);
    if (rc != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, rc, s,
		     "mod_dav_acl: could not create lock mutex");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = unixd_set_global_mutex_perms(sconf->mutex);
    if (rc != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_CRIT, rc, s,
		     "mod_dav_acl: could not set lock mutex permissions");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_pool_cleanup_register(p, sconf, cleanup_mutex, apr_pool_cleanup_null);

    /* Register DAV methods */
    iM_ACL = ap_method_register(p, "ACL");
    iM_HEAD = ap_method_register(p, "HEAD");

    dav_acl_register_hooks(p, &acl);

    return OK;
}

/** options hooks */
static dav_error *options_dav_header(request_rec *r,
                                     const dav_resource *resource,
                                     apr_text_header *phdr)
{
    apr_text_append(r->pool, phdr, "access-control");

    return NULL;
}

static dav_error *options_dav_method(request_rec *r,
                                     const dav_resource *resource,
                                     apr_text_header *phdr)
{
    apr_text_append(r->pool, phdr, "REPORT");
    apr_text_append(r->pool, phdr, "ACL");

    return NULL;
}

static
#if APACHE_PATCH
    dav_hooks_options
#else
    dav_options_provider
#endif
options =
{
    options_dav_header,
    options_dav_method,
    NULL
};

/** resource type hooks for principals */
static int get_resource_type(const dav_resource *resource,
                             const char **name, const char **uri)
{
    request_rec *r = resource->hooks->get_request_rec(resource);
    const char *pch = dav_acl_get_principal_dir(r);

    if (resource->exists && resource->collection == FALSE &&
		pch && strncmp(pch, r->filename, strlen(pch)) == 0) {
	*name = "principal";
	*uri = NS_DAV;
	return 0;
    }

    return -1;
}

static
#if APACHE_PATCH
dav_hooks_resource
#else
dav_resource_type_provider
#endif
res_hooks =
{
    get_resource_type,
    NULL
};

static void add_input_filter(request_rec *r)
{
    dav_acl_input_filter_t *f;

    if (r->method_number != M_REPORT)
	return;

    f = apr_pcalloc(r->pool, sizeof(*f));

    f->r = r;
    ap_add_input_filter(ACL_FILTER, f, r, r->connection);
}

/* initialize hooks */
static void register_hooks(apr_pool_t *p)
{
#if 0
    static const char * const dav[] = { "mod_dav.c", NULL };
    ap_hook_handler(davacl_handler, NULL, dav, APR_HOOK_MIDDLE);
#endif
    ap_hook_insert_filter(add_input_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_input_filter(ACL_FILTER, dav_acl_input_filter, NULL,
			     AP_FTYPE_RESOURCE);

    ap_hook_post_config(initialize_module, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(davacl_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);

    /* live property handling */
    dav_hook_gather_propsets(dav_acl_gather_propsets, NULL, NULL,
			     APR_HOOK_MIDDLE);
    dav_hook_find_liveprop(dav_acl_find_liveprop, NULL, NULL, APR_HOOK_MIDDLE);
    dav_acl_register_props(p);

#if APACHE_PATCH
    dav_options_register_hooks(p, "acl", &options);

    dav_resource_register_hooks(p, "acl", &res_hooks);
#else
    dav_options_provider_register(p, "acl", &options);

    dav_resource_type_provider_register(p, "acl", &res_hooks);
#endif
}

module AP_MODULE_DECLARE_DATA dav_acl_module[1] =
{{
    STANDARD20_MODULE_STUFF,	/* standard 2.0 macro */
    create_dir_config,		/* per-directory config creator */
    NULL,			/* dir config merger */
    create_server_config,	/* server config creator */
    NULL,			/* server config merger */
    dav_acl_cmds,		/* command table */
    register_hooks,		/* set up other request processing hooks */
}};

