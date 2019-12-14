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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>

#if HAVE_XATTR
#include <attr/xattr.h>
#endif

#include "acl_private.h"

static module *dav_acl_module;

/** returns a privilege error */
dav_error *dav_acl_privilege_error(request_rec *r, const char *priv,
                                   const char *desc, ...)
{
    va_list va;
    dav_error * err;
    char *pch;

    va_start(va, desc);
    pch = desc ? apr_pvsprintf(r->pool, desc, va) : NULL;
    err = dav_new_error(r->pool, HTTP_FORBIDDEN, 0, APR_SUCCESS, pch);
    va_end(va);

    err->tagname = "need-privileges";
    err->childtags = apr_psprintf(r->pool, "<D:%s/>", priv);
    return err;
}

/** dump error to apache */
int dav_acl_exec_error(request_rec *r, dav_error *err)
{
    r->status = err->status;
    r->status_line = ap_get_status_line(r->status);

    if (r->status == HTTP_FORBIDDEN) {
	xmlChar *pch = (xmlChar *) r->parsed_uri.path;
	char *pr;
	int cb;
	xmlNode *cur;
	xmlNs *ns;
	xmlDoc *doc = xmlNewDoc((const xmlChar *) XML_VERSION);

	cur = doc->children =
		xmlNewDocNode(doc, NULL, (const xmlChar *) "error", NULL);
	xmlSetNs(cur, ns = xmlNewNs(cur, (const xmlChar *) NS_DAV, NULL));

	cur = xmlNewChild(cur, ns, (xmlChar *) err->tagname, NULL);
	cur = xmlNewChild(cur, ns, (const xmlChar *) "resource", NULL);
	xmlNewChild(cur, ns, (const xmlChar *) "href", pch);

	pr = err->childtags ? strchr(err->childtags, ':') : NULL;
	if (pr) {
	    char *pe = strrchr(pr++, '/');

	    if (pe)
		*pe = '\0';
	    cur = xmlNewChild(cur, ns, (const xmlChar *) "privilege", NULL);
	    xmlNewChild(cur, ns, (const xmlChar *) pr, NULL);
	}

	xmlDocDumpFormatMemoryEnc(doc, &pch, &cb, "UTF-8", 1);

	ap_set_content_type(r, "application/xml");

	ap_rprintf(r, "%.*s", cb, pch);
	xmlFree(pch);
	xmlFreeDoc(doc);

	TRACE(r, "access error %s", pr ? pr : "");
    }
    else {
	ap_set_content_type(r, "text/html");

	if (err->desc)
	    ap_rprintf(r, "%s", err->desc);

	TRACE(r, "access error %s", err->desc ? err->desc : "");
    }

    return DONE;
}

/** return principal local directory */
const char *acl_get_principal_dir(const davacl_dir_cfg *conf)
{
    return conf->principal_dir;
}

static inline davacl_dir_cfg *config(request_rec *r)
{
    if (dav_acl_module == NULL)
	dav_acl_module = ap_find_linked_module("mod_dav_acl.c");

    return ap_get_module_config(r->per_dir_config, dav_acl_module);
}

/** same as above but based on request structure */
const char *dav_acl_get_principal_dir(request_rec *r)
{
    return acl_get_principal_dir(config(r));
}

/** returns read aggregation */
void dav_acl_get_aggregated(const dav_resource *resource, int *acl, int *cups)
{
    request_rec *r = resource->hooks->get_request_rec(resource);
    davacl_dir_cfg *conf = config(r);

    *acl = conf->acl_aggregated;
    *cups = conf->cups_aggregated;
}

/** principals base uri */
const char *dav_acl_get_principals(request_rec *r)
{
    davacl_dir_cfg *conf = config(r);

    return conf->principals;
}

/** get acl data from the _property_ database */
static int get_acl_from_db(const dav_resource *resource,
                           const davacl_dir_cfg *conf,
                           const char **ppb, int *cb)
{
    const dav_hooks_propdb *db_hooks = DBHOOKS(conf);
    dav_db *db = NULL;
    int rc = -1;
    dav_xmlns_info *xi;
    dav_prop_name name[1] = { { 0 } };

    if (db_hooks == NULL ||
	db_hooks->open(resource->pool, resource, 1, &db) != NULL || db == NULL)
	return rc;

    /* define (up front) any namespaces the db might need */
    db_hooks->define_namespaces(db, xi = dav_xmlns_create(resource->pool));

    db_hooks->first_name(db, name);

    while (name->ns != NULL) {
	if (strcmp(name->name, "acl") == 0 && strcmp(name->ns, NS_DAV) == 0) {
	    char *pch;
	    apr_text_header hdr[1] = { { 0 } };
	    int f;

	    db_hooks->output_value(db, name, xi, hdr, &f);

	    pch = (hdr->first && hdr->first->text) ?
		  strchr(hdr->first->text, '>') : NULL;
	    if (pch) {
		apr_text_header hdr_ns[1] = { { 0 } };

		*pch = 0;
		dav_xmlns_generate(xi, hdr_ns);

		*ppb = apr_psprintf(resource->pool, "%s %s>%s",
				    hdr->first->text,
				    (hdr_ns->first && hdr_ns->first->text) ?
					hdr_ns->first->text : "", pch + 1);
	    }
	    rc = *cb = *ppb ? strlen(*ppb) : 0;
	    break;
	}

	db_hooks->next_name(db, name);
    }
    db_hooks->close(db);

    return rc;
}

int acl_get_acl(const dav_resource *resource, const davacl_dir_cfg *conf,
                const char *filename, const char **ppb, int *c)
{
    *ppb = NULL;
    *c = 0;

#if HAVE_XATTR
    if (conf->use_std_property_db == FALSE) {
	int cb = getxattr(filename, DAV_ACL, NULL, 0);

	if (cb >= 0) {
	    char *pch;

	    *ppb = pch = apr_pcalloc(resource->pool, cb);
	    return *c = getxattr(filename, DAV_ACL, pch, cb);
	}
    }
#endif

    return get_acl_from_db(resource, conf, ppb, c);
}

int dav_acl_get_acl(const dav_resource *resource, const char **ppb, int *c)
{
    request_rec *r = resource->hooks->get_request_rec(resource);
    davacl_dir_cfg * conf = config(r);

    return acl_get_acl(resource, conf,
			resource->hooks->get_pathname(resource), ppb, c);
}

/** does r->uri refer to a directory? */
static int is_dir(request_rec *r, const davacl_dir_cfg *conf)
{
    struct stat st;
    char *pch;

    if (conf->principal_dir == NULL)
	return FALSE;

    pch = apr_psprintf(r->pool, "%s/%s", conf->principal_dir,
			r->user ? r->user : "");
    if (stat(pch, &st) != 0)
	return FALSE;

    return S_ISDIR(st.st_mode) ? TRUE : FALSE;
}

/**
 * resolve principal uri for r->user
 * it can be a) http://example.com/principals/[r->user]
 * or        b) http://example.com/principals/[r->user]/self
 */
const char *acl_get_principal_uri(request_rec *r, const davacl_dir_cfg *conf)
{
    char *uri = NULL;

    if (r->user && conf->principals) {
	uri = apr_psprintf(r->pool, "%s/%s", conf->principals, r->user);

	if (is_dir(r, conf))
	    uri = apr_pstrcat(r->pool, uri, "/self", NULL);
    }

    return uri;
}

const char *dav_acl_get_auth_principal(const dav_resource *resource)
{
    request_rec *r = resource->hooks->get_request_rec(resource);
    davacl_dir_cfg *conf = config(r);

    return acl_get_principal_uri(r, conf);
}

/** get group or owner uri from the property database */
static const char *get_uri_prop(const dav_resource *resource,
                                const davacl_dir_cfg *conf,
                                const char *elem)
{
    char *pch = NULL;
    const dav_hooks_propdb *db_hooks = DBHOOKS(conf);
    dav_db *db = NULL;
    dav_prop_name name[1] = { { 0 } };

    if (db_hooks == NULL ||
	db_hooks->open(resource->pool, resource, 1, &db) != NULL ||
		db == NULL)
	return NULL;

    db_hooks->first_name(db, name);

    while (name->ns != NULL) {
	if (strcmp(name->name, elem) == 0 && strcmp(name->ns, NS_DAV) == 0) {
	    apr_text_header hdr[1] = { { 0 } };
	    int f;
	    char *p;

	    db_hooks->output_value(db, name, NULL, hdr, &f);

	    pch = (hdr->first && hdr->first->text) ?
			strstr(hdr->first->text, "href>") : NULL;
	    if (pch == NULL)
		break;

	    p = strchr(pch, '<');
	    if (p) {
		*p = 0;
		pch = apr_pstrdup(resource->pool, pch + 5);
	    }
	    else {
		pch = NULL;
	    }
	    break;
	}
	db_hooks->next_name(db, name);
    }
    db_hooks->close(db);

    return pch;
}

/** get owner of a resource */
const char *acl_get_owner(const dav_resource *resource,
                          const davacl_dir_cfg *conf,
                          const char *filename) {
#if HAVE_XATTR
    if (conf->use_std_property_db == FALSE) {
	int cb = getxattr(filename, DAV_OWNER, NULL, 0);

	if (cb >= 0) {
	    char *pch = apr_pcalloc(resource->pool, cb + 1);

	    getxattr(filename, DAV_OWNER, pch, cb);
	    return pch;
	}
    }
#endif
    return get_uri_prop(resource, conf, "owner");
}

/** returns owner of a resource */
const char *dav_acl_get_owner(const dav_resource *resource)
{
    const char *filename = resource->hooks->get_pathname(resource);
    request_rec *r = resource->hooks->get_request_rec(resource);
    davacl_dir_cfg *conf = config(r);

    return acl_get_owner(resource, conf, filename);
}

/** get "group" of a resource */
const char *acl_get_group(const dav_resource *resource,
                          const davacl_dir_cfg *conf)
{
    return get_uri_prop(resource, conf, "group");
}

/** does a user belong to this group? */
static int is_child(const char *user, const char *group, acl_uid_t *aud,
                    const davacl_dir_cfg *conf, int count_loop)
{
    apr_rmm_off_t *poff = (apr_rmm_off_t*) ADDRESS(conf, aud->children);

    for ( ; *poff; poff++) {
	acl_uid_t *child = UID(conf, *poff);

	const char *name = GET_USERNAME(conf, child->user);

	if (name && strcmp(name, user) == 0) {
	    return TRUE;
	}
	else if (child->children) {
	    /* not a real proper loop checker, but prevents infinite loops */
	    if (++count_loop > LOOP_MAX)
		return -1;

	    /* child was again a group, search user from there (recursively) */
	    if (is_child(user, name, child, conf, count_loop))
		return TRUE;
	}
    }

    return FALSE;
}

/** does a user belong to a group and is group really a group */
int acl_is_user_group_member(const char *user, const char *group,
                             const davacl_dir_cfg *conf)
{
    apr_rmm_off_t uid;
    acl_uid_t *aud;
    int rc;

    if (user == NULL || group == NULL)
	return FALSE;

    /* does group refer to a group ? */
    for (uid = *conf->off_user; uid; uid = aud->next) {
	const char *pch;

	aud = UID(conf, uid);
	pch = GET_USERNAME(conf, aud->user);

	if (pch && strcmp(pch, group) == 0) {
	    if (aud->children &&
			(rc = is_child(user, group, aud, conf, 0)))
		return rc;
	    break;
	}
    }

    return FALSE;
}

/** does principal uri match with uri defined in acl */
static int uri_matches(xmlNode *node, const char *user,
                       const davacl_dir_cfg *conf)
{
    xmlChar *href = xmlNodeGetContent(node);
    const char *uri = (char *) href;
    int rc;

    if (uri && user && strcmp(uri, user) == 0) {
	xmlFree(href);
	return TRUE;
    }

    /* is uri in acl a group uri ? */
    if (uri && user && (rc = acl_is_user_group_member(user, uri, conf))) {
	xmlFree(href);
	return rc;
    }
    xmlFree(href);

    return FALSE;
}

/** does principal property match */
static int property_matches(xmlNode *node, const char *user,
                            const char *owner, request_rec *r,
                            const dav_resource *resource,
                            const davacl_dir_cfg *conf)
{
    xmlNode *prop = NULL;
    int rc;

    FOR_CHILD(prop, node) {
	if (NODE_NOT_DAV(prop)) {
	    ;
	}
	else if (NODE_MATCH(prop, "owner")) {
	    if (owner == NULL /* XXX this is an _unusual_ error case */ ||
			(owner && user && strcmp(owner, user) == 0))
		return TRUE;
	}
	else if (NODE_MATCH(prop, "group")) {
	    const char *group = acl_get_group(resource, conf);

	    if (group && user &&
			(rc = acl_is_user_group_member(user, group, conf)))
		return rc;
	}
    }

    return FALSE;
}

/** self match testing */
static int self_matches(const char *user, request_rec *r,
                        const davacl_dir_cfg *conf)
{
    const char *pch = acl_get_principal_dir(conf);
    char *group;

    if (pch == NULL) {
	TRACE_WARNING(r, "principal directory NULL !");
	return FALSE;
    }
    group = apr_psprintf(r->pool, "%s%s", conf->principals,
				r->filename + strlen(pch));

    if (group && user && strcmp(group, user) == 0)
	return TRUE;
    else if (user)
	return acl_is_user_group_member(user, group, conf);

    return FALSE;
}

/** does r->uri refer to principal resources */
static int is_resource_principal(request_rec *r, const dav_resource *resource,
                                 const davacl_dir_cfg *conf)
{
    const char *pch = acl_get_principal_dir(conf);

    if (resource->collection == FALSE &&
		pch && strncmp(pch, r->filename, strlen (pch)) == 0)
	return TRUE;

    return FALSE;
}

int dav_acl_is_resource_principal(const dav_resource *resource)
{
    request_rec *r = resource->hooks->get_request_rec(resource);
    davacl_dir_cfg *conf = config(r);

    return is_resource_principal(r, resource, conf);
}

/** check whether r->user matches with the acl principal rule */
static int principal_match(xmlNode *node, request_rec *r,
                           const dav_resource *resource,
                           const davacl_dir_cfg *conf,
                           const char *uri, const char *owner)
{
    xmlNode *child, *type = NULL;
    int rc = FALSE;

    FOR_CHILD(child, node) {
	if (NODE_NOT_DAV(child)) {
	    ;
	}
	else if (NODE_MATCH(child, "principal")) {
	    FOR_CHILD(type, child) {
		if (NODE_NOT_DAV(type)) {
		    ;
		}
		else if (NODE_MATCH(type, "all")) {
		    return TRUE;
		}
		else if (NODE_MATCH(type, "self")) {
		    /* not 100 % sure about this but i think <self> applies only
		     * to principal resources ??? */
		    if (is_resource_principal(r, resource, conf) &&
				(rc = self_matches(uri, r, conf)))
			return TRUE;
		}
		else if (NODE_MATCH(type, "property")) {
		    if ((rc = property_matches(type, uri, owner,
						r, resource, conf)))
			return TRUE;
		}
		else if (NODE_MATCH(type, "href")) {
		    if ((rc = uri_matches(type, uri, conf)))
			return TRUE;
		}
		else if (NODE_MATCH(type, "authenticated")) {
		    if (r->user)
			return TRUE;
		}
		else if (NODE_MATCH(type, "unauthenticated")) {
		    if (r->user == NULL)
			return TRUE;
		}
	    }
	}
	else if (NODE_MATCH(child, "invert")) {
	    FOR_CHILD(type, child) {
		if (NODE_NOT_DAV(type)) {
		    ;
		}
		else if (NODE_MATCH(type, "all")) {
		    return FALSE;
		}
		else if (NODE_MATCH(type, "self")) {
		    /* not 100 % sure about this but i think <self> applies only
		     * to principal resources ??? */
		    if (is_resource_principal(r, resource, conf) &&
				(rc = self_matches(uri, r, conf)) <= 0)
			return TRUE;
		}
		else if (NODE_MATCH(type, "property")) {
		    if ((rc = property_matches(type, uri, owner,
						r, resource, conf)) <= 0)
			return TRUE;
		}
		else if (NODE_MATCH(type, "href")) {
		    if ((rc = uri_matches(type, uri, conf)) <= 0)
			return TRUE;
		}
		else if (NODE_MATCH(type, "authenticated")) {
		    if (r->user == NULL)
			return TRUE;
		}
		else if (NODE_MATCH(type, "unauthenticated")) {
		    if (r->user)
			return TRUE;
		}
	    }
	}
    }

    return rc;
}

/**
 * check for access
 * if/when aggregated read & write used in the test, they must be on list
 * rc: 1 access allowed
 *     0 access denied
 *    -1 access not defined in this rule
 */
static int has_access(xmlNode *node, const dav_prop_name *name, int count)
{
    xmlNode *type, *priv, *val;
    int i;

    /* check whether <grant> or <deny> access */
    FOR_CHILD(type, node) {
	if (NODE_NOT_DAV(type)) {
	    ;
	}
	else if (NODE_MATCH(type, "grant")) {
	    FOR_CHILD(priv, type) {
		if (NODE_NOT_DAV(priv) ||
		    NODE_MATCH(priv, "privilege") == FALSE)
		    continue;

		FOR_CHILD(val, priv) {
		    if (NODE_NOT_DAV(val))
			continue;

		    for (i = 0; i < count; i++)
			if (NODE_MATCH(val, "all"))
			    return TRUE;
			else if (strcmp((char *) val->name, name[i].name) == 0 &&
				 val->ns && val->ns->href && name[i].ns &&
				 strcmp((char *) val->ns->href, name[i].ns) == 0)
			    return TRUE;
		}
	    }
	}
	else if (NODE_MATCH(type, "deny")) {
	    FOR_CHILD(priv, type) {
		if (NODE_NOT_DAV(priv) ||
		    NODE_MATCH(priv, "privilege") == FALSE)
		    continue;

		FOR_CHILD(val, priv) {
		    if (NODE_NOT_DAV(val)) {
			;
		    }
		    else if (NODE_MATCH(val, "all")) {
			return FALSE;
		    }
		    else if (NODE_MATCH(val, "write")) {
			for (i = 0; i < count; i++)
			    if (strcmp(name[i].name, "write") == 0 &&
					name[i].ns && strcmp(name[i].ns, NS_DAV) == 0)
				return FALSE;
		    }
		    else if (NODE_MATCH(val, "read")) {
			for (i = 0; i < count; i++)
			    if (strcmp(name[i].name, "read") == 0 &&
					name[i].ns && strcmp(name[i].ns, NS_DAV) == 0)
				return FALSE;
		    }
		    else {
			for (i = 0; i < count; i++)
			    if (strcmp((char *) val->name, name[i].name) == 0 &&
				val->ns && val->ns->href && name[i].ns &&
					strcmp((char *) val->ns->href, name[i].ns) == 0)
				return FALSE;
		    }
		}
	    }
	}
    }

    return -1;
}

/**
 * check for inherited acls
 * only supports local acls on the same server
 */
static dav_error *has_inherited(xmlNode *node, const dav_prop_name *priv,
                                int count, request_rec *r,
                                const davacl_dir_cfg *conf, int count_loop)
{
    xmlNode *type, *child;
    dav_error *err = NULL;

    FOR_CHILD(type, node) {
	if (NODE_NOT_DAV(type)) {
	    ;
	}
	else if (NODE_MATCH(type, "inherited")) {
	    FOR_CHILD(child, type) {
		xmlChar *uri;
		dav_resource *resource = NULL;
		dav_lookup_result lookup[1] = { { 0 } };

		if (NODE_NOT_DAV(child) ||
			NODE_MATCH(child, "href") == FALSE)
		    continue;

		uri = xmlNodeGetContent(child);
		*lookup = dav_lookup_uri((char *) uri, r, TRUE);

		if (lookup->rnew->status != HTTP_OK) {
		    err = dav_acl_privilege_error(r, priv->name,
				"Inherited acl <%s> could not be located "
				"(resource in a different server ?) !", uri);
		}
		else {
		    err = conf->provider->repos->
			  get_resource(lookup->rnew, NULL, NULL, 0, &resource);
		    if (err == NULL) {
			if (resource->exists == FALSE)
			    err = dav_acl_privilege_error(lookup->rnew,
					priv->name, "Inherited acl <%s> "
					"could not be read!", uri);
			else
			    err = acl_check_req(lookup->rnew,
						lookup->rnew->filename,
						resource, conf, priv, count,
						++count_loop);
		    }
		}
		ap_destroy_sub_req(lookup->rnew);
		xmlFree(uri);

		if (err)
		    return err;

		/* not a real proper loop test but prevents infinite ones */
		if (count_loop > LOOP_MAX)
		    return dav_acl_privilege_error(r, priv->name,
					"Detected a loop (max: %u) "
					"with inherited acls", count_loop);
	    }
	}
    }

    return NULL;
}

/**
 * first read acl, then locate principals in each acl and finally
 * check if access rights allow the request
 */
dav_error *acl_check_req(request_rec *r, const char *filename,
                         const dav_resource *resource,
                         const davacl_dir_cfg *conf, const dav_prop_name *priv,
                         int count, int count_loop)
{
    int rc, size;
    const char *pch, *desc = NULL, *uri;
    dav_error *err = NULL;
    xmlDoc *doc;
    xmlNode *node;
    const char *owner = acl_get_owner(resource, conf, filename);

    rc = acl_get_acl(resource, conf, filename, &pch, &size);

    if (rc < 0) {
	/* no owner or owner exists but has no exclusive full rights */
	if (owner == NULL || conf->owner_full_rights == FALSE) {
	    return NULL;
	}
	else {
	    const char *uri = acl_get_principal_uri(r, conf);

	    if (uri && owner && strcmp(uri, owner) == 0)
		return NULL;
	    else
		return dav_acl_privilege_error(r, count ? priv[count - 1].name :
							"unknown", NULL);
	}
    }

    if (owner == NULL)
	TRACE_WARNING(r, "resource:%s has no owner, but acl (%d) exists ???",
			filename, size);

    /* do acl check */
    doc = xmlParseMemory(pch, size);
    node = doc ? doc->children : NULL;
    uri = acl_get_principal_uri(r, conf);
    rc = -1;

    FOR_CHILD(node, node) {
	if (NODE_NOT_DAV(node)) {
	    ;
	}
	else if (NODE_MATCH(node, "ace")) {
	    rc = principal_match(node, r, resource, conf, uri, owner);

	    if (rc < 0) {
		TRACE_WARNING(r, "Loop detected with resource:%s", filename);
		desc = "Loop detected within principals (groups)";
		break;
	    }

	    if (rc && (rc = has_access(node, priv, count)) >= 0) {
		/**
		 * principal match found, check access rights
		 * rc: 0 == no access
		 * rc: 1 == access allowed
		 * rc:-1 == privilege not defined
		 * check the possible inherited acls if such exist
		 */
		if (rc && (err = has_inherited(node, priv, count, r, conf,
						count_loop++))) {
		    rc = 0;

		    if (err && err->desc)
			desc = err->desc;
		}
		break;
	    }
	}
    }
    xmlFreeDoc(doc);

    if (rc <= 0) {
	TRACE (r, "acl <%s> priviledge error %s user:%s owner:%s rc:%d",
		count ? priv[count - 1].name : "unknown", desc ? desc : "",
		uri, owner, rc);

	return dav_acl_privilege_error(r, count ? priv[count - 1].name : "unknown",
					"%s (principal:<%s>)", desc ? desc : "",
					uri ? uri : "");
    }

    return NULL;
}

static const char *resource_privs(request_rec *r, const dav_resource *resource,
                                  davacl_server_cfg *sconf,
                                  davacl_dir_cfg *conf, const char *acl,
                                  int size, const char *owner, const char *uri)
{
    static const dav_prop_name privs[] = {
	{ NS_DAV, "all" },
	{ NS_DAV, "read-acl" },
	{ NS_DAV, "read" },
	{ NS_DAV, "read-current-user-privilege-set" },
	{ NS_DAV, "write-acl" },
	{ NS_DAV, "unlock" },
	{ NS_DAV, "write" },
	{ NS_DAV, "write-content" },
	{ NS_DAV, "write-properties" },
	{ NS_DAV, "bind" },
	{ NS_DAV, "unbind" } };
    int i, rc;
    xmlDoc *doc;
    char *resp = apr_pstrdup(r->pool, "");

    doc = xmlParseMemory(acl, size);

    acl_lock(sconf);

    for (i = 0; i < ARRAY_SIZE(privs) - !resource->collection * 2; i++) {
	xmlNode *node = doc ? doc->children : NULL;

	FOR_CHILD(node, node) {
	    if (NODE_NOT_DAV(node)) {
		;
	    }
	    else if (NODE_MATCH(node, "ace")) {
		rc = principal_match(node, r, resource, conf, uri, owner);

		if (rc < 0) {
		    node = NULL;
		    break;
		}
		if (rc == 0)
		    continue;

		/* principal match found */
		rc = has_access(node, &privs[i], 1);
		if (rc < 0)
		    continue;

		/* inherited check */
		if (rc && has_inherited(node, &privs[i], 1, r, conf, 0))
		    rc = 0;

		if (i == 0) {
		    return rc ? "<D:privilege><D:all/></D:privilege>\n" : "";
		}
		else if (rc) {
		    resp = apr_pstrcat(r->pool, resp, "<D:privilege><D:",
					privs[i].name, "/></D:privilege>\n", NULL);

		    if (strcmp(privs[i].name, "write") == 0)
			break;
		    else if (strcmp(privs[i].name, "read") == 0)
			i++;
		}
	    }
	}
    }
    acl_unlock(sconf);

    xmlFreeDoc(doc);

    return resp;
}

/** report acls of a resource for the principal */
const char *dav_acl_get_privs(const dav_resource *resource)
{
    request_rec *r = resource->hooks->get_request_rec(resource);
    davacl_dir_cfg *conf = config(r);
    davacl_server_cfg *sconf = ap_get_module_config(r->server->module_config,
							dav_acl_module);
    const char *owner, *pch, *uri;
    int rc, size;

    rc = acl_get_acl(resource, conf, r->filename, &pch, &size);
    owner = acl_get_owner(resource, conf, r->filename);
    uri = acl_get_principal_uri(r, conf);

    if (rc < 0) {
	if (owner == NULL || (uri && owner && strcmp(uri, owner) == 0))
	    return "<D:privilege><D:all/></D:privilege>";
	else
	    return "";
    }
    else {
	return resource_privs(r, resource, sconf, conf, pch, size, owner, uri);
    }
}

/** returns a list of group uris into which a principal belongs to */
const char *dav_acl_get_group_membership(const dav_resource *resource)
{
    request_rec *r;
    davacl_dir_cfg *conf;
    acl_uid_t *aud;
    apr_rmm_off_t off;
    char *value = NULL, *user;
    const char *pch;

    r = resource->hooks->get_request_rec(resource);
    conf = config(r);
    pch = acl_get_principal_dir(conf);

    if (pch == NULL || conf->principals == NULL)
	return NULL;

    user = apr_psprintf(r->pool, "%s%s", conf->principals,
			r->filename + strlen (pch));

    for (off = *conf->off_user; user && off; off = aud->next) {
	const char *group;

	aud = UID(conf, off);
	group = GET_USERNAME(conf, aud->user);

	if (aud->children && acl_is_user_group_member(user, group, conf))
	    value = apr_pstrcat(r->pool, value ? value : "",
				"<D:href>", group, "</D:href>\n", NULL);
    }

    return value;
}

/** get principal properties from db */
static void get_principal_props(dav_db *db, const dav_hooks_propdb *db_hooks,
                                char **puri, apr_text **group, char **ppch)
{
    dav_prop_name name[1] = { { 0 } };
    char *uri;

    *puri = NULL;
    *group = NULL;
    *ppch = NULL;

    db_hooks->first_name(db, name);

    while (name->ns != NULL) {
	apr_text_header hdr[1] = { { 0 } };
	int f;

	db_hooks->output_value(db, name, NULL, hdr, &f);

	if (strcmp(name->name, "principal-URL") == 0 &&
	    strcmp(name->ns, NS_DAV) == 0 && hdr->first && hdr->first->text &&
		(uri = strstr(hdr->first->text, "href>")) != NULL) {
	    char *pr;

	    uri += 5;
	    if ((pr = strchr(uri, '<')) != NULL)
		*pr = 0;

	    *puri = uri;
	}
	else if (strcmp(name->name, "group-member-set") == 0 &&
		 strcmp(name->ns, NS_DAV) == 0) {
	    *group = hdr->first;
	}
	else if (strcmp(name->name, "displayname") == 0 &&
		 strcmp(name->ns, NS_DAV) == 0 &&
		 hdr->first && hdr->first->text) {
	    char *dn = strstr(hdr->first->text, "displayname>");
	    if (dn == NULL)
		continue;

	    *ppch = dn + 12;

	    if ((dn = strchr(*ppch, '<')) != NULL)
		*dn = 0;
	}

	db_hooks->next_name(db, name);
    }
}

/** add new principal to the shared memory */
static apr_rmm_off_t add_principal(const request_rec *r, davacl_dir_cfg *conf,
                                   const char *uri, const char *display_name,
                                   const char *group)
{
    apr_rmm_off_t user, *p;
    acl_uid_t aud[1] = { { 0 } };

    if (uri == NULL) {
	TRACE_ERROR(r, "mod_dav_acl: could not store info for user: no URI");
	return 0;
    }

    user = apr_rmm_calloc(conf->rmm, sizeof(acl_uid_t));
    if (user == 0) {
	TRACE_ERROR(r, "mod_dav_acl: could not store info for user %s, "
		    "shared mem too small", uri);
	return 0;
    }

    for (p = conf->off_user; *p; p = &(UID(conf, *p))->next)
	;

    *p = user;

    if (group)
	aud->children = (apr_rmm_off_t) group;

    aud->user = apr_rmm_malloc(conf->rmm, strlen (uri) + 1);
    if (aud->user == 0) {
	TRACE_ERROR(r, "mod_dav_acl: could not store info for user %s, "
			"shared mem too small ?", uri);
	return 0;
    }
    strcpy(USERNAME(conf, aud->user), uri);

    if (display_name) {
	aud->displayname =
		apr_rmm_malloc(conf->rmm, strlen (display_name) + 1);

	if (aud->displayname)
	    strcpy(USERNAME(conf, aud->displayname), display_name);
	else
	    TRACE_ERROR(r, "mod_dav_acl: could not store displayname for user "
			   "%s, shared mem too small ?", uri);
    }
    *UID(conf, user) = *aud;

    return user;
}

/** get all principals into shared memory */
static void get_user_ids(const dav_provider *provider, const char *subdir,
                         davacl_dir_cfg *conf, const request_rec *r,
                         apr_pool_t *subpool, int recur)
{
    DIR *dp;
    struct stat st;
    const dav_hooks_propdb *db_hooks = DBHOOKS(conf);
    const dav_hooks_repository *repos = REPOS(conf);
    struct dirent *res = NULL;
    const char *dir = subdir ? subdir : conf->principal_dir;
    struct dirent entry[offsetof(struct dirent, d_name) +
			pathconf(dir, _PC_NAME_MAX) + 1];

    if (conf->principal_dir == NULL || conf->principals == NULL ||
		db_hooks == NULL || repos == NULL)
	return;

    if ((dp = opendir(dir)) == NULL)
	return;

    for ( ; readdir_r(dp, entry, &res) == 0 && res != NULL; ) {
	char *file;

	/* no current/parent dir or hidden file == .* */
	if (entry->d_name[0] == '.')
	    continue;

	file = apr_pstrcat(subpool, dir, "/", entry->d_name, NULL);
	if (stat(file, &st) != 0)
	    continue;

	if ((st.st_mode & S_IFDIR) == S_IFDIR && recur < MAX_RECURSION) {
	    get_user_ids(provider, file, conf, r, subpool, ++recur);
	}
	else if ((st.st_mode & S_IFREG) == S_IFREG) {
	    dav_resource *resource = NULL;
	    dav_error *err = NULL;
	    dav_db *db = NULL;
	    char *uri = NULL, *display = NULL;
	    apr_text *group = NULL;

	    request_rec *rf = apr_pcalloc(subpool, sizeof(*rf));
	    rf->filename = file;
	    rf->uri = apr_pstrcat(rf->pool = subpool, conf->principals,
				  file + strlen (conf->principal_dir), NULL);
	    apr_stat(&rf->finfo, rf->filename, APR_FINFO_MIN, rf->pool);
	    err = repos->get_resource(rf, NULL, NULL, 0, &resource);
	    if (err)
		continue;

	    db_hooks->open(resource->pool, resource, 1, &db);
	    if (db == NULL)
		continue;

	    if (resource->exists == FALSE || resource->collection) {
		db_hooks->close (db);
		continue;
	    }

	    get_principal_props(db, db_hooks, &uri, &group, &display);

	    if (uri)
		add_principal(r, conf, uri, display, group != NULL ?
			      apr_pstrdup (subpool, group->text) : NULL);

	    db_hooks->close(db);
	}
    }
    closedir(dp);
}

/** find aud for a given user */
static apr_rmm_off_t find_aud(davacl_dir_cfg *conf, const char *user)
{
    apr_rmm_off_t off;
    acl_uid_t *aud;

    for (off = *conf->off_user; off; off = aud->next) {
	char *pch;

	aud = UID(conf, off);
	pch = GET_USERNAME(conf, aud->user);

	if (pch && strcmp(pch, user) == 0)
	    return off;
    }

    return 0;
}

/** resolve all groups first by finding list of off_t */
static apr_rmm_off_t *resolve_auds(davacl_dir_cfg *conf,
                                   const char *groups, int *pc)
{
    apr_rmm_off_t *pp = NULL, off;
    int c = 0;

    if (groups) {
	char *pch = (char *) groups, *s = strstr(pch, "href>");

	for ( ; pch && s; s = pch ? strstr(pch, "href>") : NULL) {
	    pch = s + 5;

	    if ((s = strchr(pch, '<')) != NULL)
		*s = 0;

	    off = find_aud(conf, pch);
	    if (off) {
		pp = realloc(pp, (c + 2) * sizeof(*pp));
		pp[c++] = off;
		pp[c] = 0;
	    }

	    pch = s ? strchr(s + 1, '>') : NULL;
	}
    }
    *pc = c;

    return pp;
}

/** final resolve of groups */
static void resolve_groups(davacl_dir_cfg *conf, const request_rec *r,
                           apr_pool_t *pool)
{
    apr_rmm_off_t off, *pp = NULL;
    acl_uid_t *aud;

    for (off = *conf->off_user; off; off = (UID(conf, off))->next) {
	int c;

	aud = UID(conf, off);
	if (aud->children == 0)
	    continue;

	pp = resolve_auds(conf, (char *) aud->children, &c);

	if (c) {
	    aud->children = apr_rmm_malloc(conf->rmm, (c + 1) * sizeof(*pp));

	    if (aud->children)
		memcpy(UID(conf, aud->children), pp, (c + 1) * sizeof(*pp));
	    else
		TRACE_ERROR(r, "mod_dav_acl: shared mem too small ?");
	}
	else {
	    aud->children = 0;
	}

	*UID(conf, off) = *aud;
	free(pp), pp = NULL;
    }
}

/** shared memory initialization */
void acl_shm_init(const request_rec *r, davacl_dir_cfg *conf)
{
    apr_status_t rc;

    if (conf == NULL || conf->shm)
	return;

    conf->provider = dav_lookup_provider(DAV_DEFAULT_PROVIDER);

    rc = apr_shm_attach(&conf->shm, conf->shared_mem_file, conf->pool);
    if (rc != APR_SUCCESS) {
	/* create shared memory for principal storage */
	rc = apr_shm_create(&conf->shm, conf->shared_mem,
			    conf->shared_mem_file, conf->pool);
	if (rc != APR_SUCCESS) {
	    char sz[100];

	    ap_log_error(APLOG_MARK, APLOG_CRIT, rc, r->server,
			 "mod_dav_acl: could not create shared memory '%s' "
			 "(unlinking, rc:%d), error:%s", conf->shared_mem_file,
			 unlink(conf->shared_mem_file),
			 apr_strerror(rc, sz, sizeof(sz)));
	    conf->shm = NULL;
	    return;
	}
    }

    if (conf->shm &&
	(rc = apr_rmm_init(&conf->rmm, NULL,
		apr_shm_baseaddr_get(conf->shm) + sizeof(apr_rmm_off_t),
		conf->shared_mem - sizeof(apr_rmm_off_t), conf->pool)) ==
								APR_SUCCESS) {
	apr_pool_t *pool;

	conf->off_user = apr_shm_baseaddr_get(conf->shm);
	*conf->off_user = 0;

	apr_pool_create(&pool, NULL);
	get_user_ids(conf->provider, NULL, conf, r, pool, 0);
	resolve_groups(conf, r, pool);
	apr_pool_destroy(pool);
    }
}

void acl_store_owner(request_rec *r, const dav_resource *resource,
                     davacl_dir_cfg *conf)
{
    dav_prop_name prop[] = {
	{ NS_DAV, "owner" },
	{ NS_DAV, "principal-URL" },
	{ NS_DAV, "displayname" } };
    apr_xml_elem el[] = {
	{ .name = "owner", 0 },
	{ .name = "principal-URL", 0 },
	{ .name = "displayname", 0 },
	{ .name = "href", 0 },
	{ .name = "href", 0 } };
    apr_text text[] = { { 0 }, { 0 }, { 0 } };
    apr_array_header_t *ns;

    el[0].first_child = &el[3];
    text[0].text = acl_get_principal_uri(r, conf);
    el[3].first_cdata.first = &text[0];

    ns = apr_array_make(resource->pool, 2, sizeof(const char *));
    *(const char **) apr_array_push(ns) = NS_DAV;

    /* storing a principal resource, most likely a group */
    if (r->method_number == M_PUT) {
	const char *pch = acl_get_principal_dir(conf);

	if (resource->collection == FALSE &&
		pch && strncmp(pch, r->filename, strlen(pch)) == 0) {
	    char *pr = strrchr(r->filename, '/');

	    el[1].first_child = &el[4];
	    el[4].first_cdata.first = &text[1];
	    text[1].text = apr_psprintf(r->pool, "%s%s", conf->principals,
					r->filename + strlen (pch));

	    el[2].first_cdata.first = &text[2];

	    if (pr != NULL && strcmp(pr + 1, "self") == 0) {
		const char *ps;

		*pr = '\0';
		ps = strrchr(r->filename, '/');

		if (ps != NULL)
		    text[2].text = apr_psprintf(r->pool, "%s", ps + 1);
		else
		    text[2].text = apr_psprintf(r->pool, "%s", pr + 1);
		*pr = '/';
	    }
	    else {
		text[2].text = apr_psprintf(r->pool, "%s", pr ? pr + 1 : "?");
	    }
	}
    }
    #if HAVE_XATTR
    if (conf->use_std_property_db == FALSE) {
	const char *file = resource->hooks->get_pathname(resource);
	int rc;

	rc = setxattr(file, DAV_OWNER, text[0].text, strlen(text[0].text), 0);
	if (rc == 0 && el[1].first_child == NULL)
	    return;

	if (rc != 0)
	    TRACE_WARNING(r, "Owner storage failed to EAs for %s. "
			  "(EAs not enabled in the filesystem ?)", file);
    }
    #endif
    {
	const dav_hooks_propdb *db_hooks = DBHOOKS(conf);
	dav_db *db = NULL;
	dav_namespace_map *map = NULL;

	if (db_hooks == NULL)
	    return;

	/* this writing is _slow_ with some machines, db problem? */
	db_hooks->open(resource->pool, resource, 0, &db);
	if (db == NULL)
	    return;

	db_hooks->map_namespaces(db, ns, &map);
	db_hooks->store(db, prop, el, map);

	if (el[1].first_child) {
	    db_hooks->store(db, prop + 1, el + 1, map);
	    db_hooks->store(db, prop + 2, el + 2, map);
	}

	db_hooks->close(db);
    }
}

void acl_update_principal(request_rec *r, const dav_resource *resource,
                          davacl_dir_cfg *conf)
{
    dav_db *db = NULL;
    const dav_hooks_propdb *db_hooks = DBHOOKS(conf);
    char *uri = NULL, *display = NULL;
    apr_text *group = NULL;
    apr_rmm_off_t off;

    if (db_hooks == NULL)
	return;

    db_hooks->open(resource->pool, resource, 1, &db);
    if (db == NULL)
	return;

    get_principal_props(db, db_hooks, &uri, &group, &display);

    if (uri &&
	(off = (r->method_number == M_PUT && r->status == 201) ?
			add_principal(r, conf, uri, display, NULL) :
			find_aud(conf, uri))) {
	apr_rmm_off_t *pp = NULL;
	int c = 0;
	acl_uid_t *aud = UID(conf, off);

	if (group)
	    pp = resolve_auds(conf, group->text, &c);

	if (aud->children)
	    apr_rmm_free(conf->rmm, aud->children), aud->children = 0;

	if (c) {
	    aud->children = apr_rmm_malloc(conf->rmm, (c + 1) * sizeof(*pp));

	    if (aud->children)
		memcpy(UID(conf, aud->children), pp, (c + 1) * sizeof(*pp));
	    else
		TRACE_ERROR (r, "mod_dav_acl: shared mem too small ?");
	}

	if (aud->displayname)
	    apr_rmm_free(conf->rmm, aud->displayname), aud->displayname = 0;

	if (display) {
	    aud->displayname = apr_rmm_malloc(conf->rmm, strlen(display) + 1);

	    if (aud->displayname)
		strcpy(USERNAME(conf, aud->displayname), display);
	    else
		TRACE_ERROR(r, "mod_dav_acl: shared mem too small ?");
	}

	*UID(conf, off) = *aud;
	free(pp), pp = NULL;
    }
    db_hooks->close(db);
}

void acl_update_all_principals(request_rec *r, davacl_dir_cfg *conf)
{
    apr_pool_t *pool;
    apr_rmm_off_t off;

    for (off = *conf->off_user; off; ) {
	acl_uid_t *aud = UID(conf, off);
	apr_rmm_off_t next = aud->next;

	if (aud->user)
	    apr_rmm_free(conf->rmm, aud->user);

	if (aud->displayname)
	    apr_rmm_free(conf->rmm, aud->displayname);

	if (aud->children)
	    apr_rmm_free(conf->rmm, aud->children);

	apr_rmm_free(conf->rmm, off);
	off = next;
    }

    *conf->off_user = 0;
    apr_pool_create(&pool, NULL);
    get_user_ids(conf->provider, NULL, conf, r, pool, 0);
    resolve_groups(conf, r, pool);
    apr_pool_destroy(pool);
}


/** check prop name privilege */
DAV_DECLARE(dav_error *) dav_acl_check(request_rec *r,
                                        const dav_resource *resource,
                                        const dav_prop_name *privs, int c)
{
    dav_error *err;
    const char *filename;
    const dav_hooks_repository *repos;
    davacl_dir_cfg *conf = config(r);
    davacl_server_cfg *sconf = ap_get_module_config(r->server->module_config,
							dav_acl_module);

    if (conf == NULL || sconf == NULL) {
	TRACE_WARNING(r, "Internal server error, no configs");
	return NULL;
    }

    acl_lock(sconf);

    if (conf->shm == NULL)
	acl_shm_init(r, conf);

    repos = REPOS(conf);
    filename = repos ? repos->get_pathname(resource) : NULL;
    err = acl_check_req(r, filename, resource, conf, privs, c, 0);
    acl_unlock(sconf);

    return err;
}

DAV_DECLARE(dav_error *) dav_acl_store_owner(request_rec *r,
                                              const dav_resource *resource)
{
    if (resource->acls == NULL) {
        const dav_acl_provider *acl = dav_get_acl_providers("acl");

	if (acl)
	    acl->acl_post_processing(r, resource, 1);
    }
    else {
        resource->acls->acl_post_processing(r, resource, 1);
    }

    return NULL;
}

/** read request body */
int dav_acl_read_body(request_rec *r, dav_buffer *buffer)
{
    apr_bucket_brigade *bb;
    int seen_eos = 0;

    if (buffer == NULL)
	return -1;

    if (buffer->buf == NULL)
	dav_buffer_init(r->pool, buffer, "");

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    do {
	apr_bucket *b;
	apr_status_t rv;

	rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
			    APR_BLOCK_READ, HUGE_STRING_LEN);
	if (rv != APR_SUCCESS) {
	    apr_brigade_destroy(bb);
	    return -1;
	}

	for (b = APR_BRIGADE_FIRST(bb);
	     b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
	    const char *data;
	    apr_size_t len;

	    if (APR_BUCKET_IS_EOS(b)) {
		seen_eos = 1;
		break;
	    }

	    if (APR_BUCKET_IS_METADATA(b))
		continue;

	    /* read */
	    rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
	    if (rv != APR_SUCCESS) {
		apr_brigade_destroy (bb);
		return -1;
	    }
	    dav_buffer_place_mem(r->pool, buffer, data, len, 1);
	    buffer->cur_len += len;
	}

	apr_brigade_cleanup(bb);
    } while (seen_eos == 0) ;

    apr_brigade_destroy(bb);
    buffer->buf[buffer->cur_len] = 0;

    return 0;
}

dav_error * acl_store_acl(request_rec *r, dav_resource *resource,
                          davacl_dir_cfg *conf, dav_buffer *buffer)
{
    apr_xml_doc *doc = NULL;
    apr_xml_parser *parser = apr_xml_parser_create(resource->pool);
	apr_status_t rv;

    if ((rv = apr_xml_parser_feed(parser, buffer->buf, buffer->cur_len))) {
	char sz[100] = "";

	apr_xml_parser_geterror(parser, sz, sizeof(sz));
	apr_xml_parser_done(parser, &doc);

	return dav_new_error(resource->pool,
				HTTP_INTERNAL_SERVER_ERROR, 0, rv, sz);
    }

    rv = apr_xml_parser_done(parser, &doc);

    if (doc == NULL || strcmp(doc->root->name, "acl"))
	return dav_new_error(resource->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
		rv, "ACL could not be set ! document root element not <acl>");

    #if HAVE_XATTR
    if (conf->use_std_property_db == FALSE) {
	int rc = setxattr(resource->hooks->get_pathname (resource),
			  DAV_ACL, buffer->buf, buffer->cur_len, 0);
	if (rc == 0)
	    return NULL;

	TRACE_WARNING(r, "ACL could not be set ! Extended attributes "
			"not enabled on the server? Storing to standard db");
    }
    #endif
    {
	const dav_hooks_propdb *db_hooks = DBHOOKS(conf);
	dav_db *db = NULL;
	dav_prop_name acl[1] = { { NS_DAV, "acl" } };
	apr_array_header_t *ns;
	dav_namespace_map *map = NULL;
	dav_error *err;

	if (db_hooks == NULL)
	    return dav_new_error(resource->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
				APR_SUCCESS, "ACL could not be set ! db_hooks == NULL");

	ns = apr_array_make(resource->pool, 2, sizeof (const char *));
	*(const char **) apr_array_push(ns) = NS_DAV;

	/* this is pretty slow (writing) */
	if ((err = db_hooks->open(resource->pool, resource, 0, &db)))
	    return err;

	if (db == NULL)
	    return dav_new_error(resource->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
					APR_SUCCESS, "ACL could not be set ! db == NULL");

	db_hooks->map_namespaces(db, ns, &map);
	db_hooks->store(db, acl, doc->root, map);
	db_hooks->close(db);
    }

    return NULL;
}

/** convert libxml2 formatted document into parsed apr-util format */
apr_xml_doc *dav_acl_get_prop_doc(request_rec *r, const xmlNode *n)
{
    xmlChar *pch;
    int i, cb;
    apr_xml_parser *parser;
    apr_xml_doc *res;
    xmlDoc *doc = xmlNewDoc((const xmlChar *) XML_VERSION);
    xmlNs *ns, **pns = xmlGetNsList(n->doc, (xmlNode *) n);

    doc->children = xmlNewDocNode(doc, NULL,
					(const xmlChar *) "propfind", NULL);

    for (i = 0; pns && pns[i]; i++) {
	ns = xmlNewNs(doc->children, pns[i]->href, pns[i]->prefix);

	if (strcmp((char *) pns[i]->href, NS_DAV) == 0)
	    xmlSetNs(doc->children, ns);
    }
    xmlFree(pns);
    xmlAddChild(doc->children, xmlCopyNode((xmlNode *) n, 1));
    xmlDocDumpFormatMemoryEnc(doc, &pch, &cb, "UTF-8", 1);
    parser = apr_xml_parser_create(r->pool);
    apr_xml_parser_feed(parser, (char *) pch, cb);
    apr_xml_parser_done(parser, &res);
    xmlFreeDoc(doc);
    xmlFree(pch);

    return res;
}

/** read body if someone else is "stealing" it */
apr_status_t dav_acl_input_filter(ap_filter_t *f, apr_bucket_brigade *pbb_out,
                                  ap_input_mode_t emode, apr_read_type_e eblock,
                                  apr_off_t nbytes)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    dav_acl_input_filter_t *pctx;
    apr_status_t ret;

    if ((pctx = f->ctx))
	pctx->pbb = apr_brigade_create(r->pool, c->bucket_alloc);
    else
	return !APR_SUCCESS;

    if (APR_BRIGADE_EMPTY(pctx->pbb)) {
	ret = ap_get_brigade(f->next, pctx->pbb, emode, eblock, nbytes);

	if (emode == AP_MODE_EATCRLF || ret != APR_SUCCESS)
	    return ret;
    }

    if (pctx->buffer.buf == NULL)
	dav_buffer_init(r->pool, &pctx->buffer, "");

    while (!APR_BRIGADE_EMPTY(pctx->pbb)) {
	apr_bucket *out, *in = APR_BRIGADE_FIRST(pctx->pbb);
	const char *data;
	apr_size_t len;
	char *buf;

	if (APR_BUCKET_IS_EOS(in)) {
	    APR_BUCKET_REMOVE(in);
	    APR_BRIGADE_INSERT_TAIL(pbb_out, in);
	    break;
	}
	ret = apr_bucket_read(in, &data, &len, eblock);
	if (ret != APR_SUCCESS)
	    return ret;

	buf = apr_bucket_alloc(len, c->bucket_alloc);
	memcpy(buf, data, len);

	dav_buffer_place_mem(r->pool, &pctx->buffer, buf, len, 1);
	pctx->buffer.cur_len += len;

	out = apr_bucket_heap_create(buf, len, apr_bucket_free,
					c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(pbb_out, out);
	apr_bucket_delete(in);
    }
    pctx->buffer.buf[pctx->buffer.cur_len] = 0;

    return APR_SUCCESS;
}

/** get prop value from internal db */
const char *dav_acl_get_prop(request_rec *r,
                             const dav_resource *resource,
                             const dav_provider *provider,
                             const dav_prop_name *prop)
{
    const char *pch = NULL;

    if (resource == NULL || provider == NULL || provider->propdb == NULL)
	return NULL;

    const dav_hooks_propdb *db_hooks = provider->propdb;
    dav_db *db = NULL;
    dav_prop_name name[1] = { { NULL, NULL } };

    db_hooks->open(resource->pool, resource, 1, &db);

    if (db != NULL) {
	db_hooks->first_name(db, name);

	while (name->ns != NULL) {
	    apr_text_header hdr[1] = { { 0 } };
	    int f;

	    if (name->name && prop->name && strcmp(name->name, prop->name) == 0 &&
		((name->ns && prop->ns && strcmp(name->ns, prop->ns) == 0) ||
			(!name->ns && !prop->ns))) {
		db_hooks->output_value(db, name, NULL, hdr, &f);

		pch = hdr->first->text;
		break;
	    }
	    db_hooks->next_name(db, name);
	}
	db_hooks->close(db);
    }

    return pch;
}

/** find the latest modification time in a directory */
void dav_acl_last_mtime(const char *subdir, request_rec *r,
                        apr_pool_t *pool, int recur)
{
    struct dirent *res = NULL;
    DIR *dp;
    int rc;
    const char *directory = subdir ? subdir : r->filename;
    struct dirent entry[offsetof(struct dirent, d_name) +
			pathconf(directory, _PC_NAME_MAX) + 1];

    if (subdir == NULL)
	r->mtime = 0;

    rc = apr_stat(&r->finfo, directory, APR_FINFO_MIN, pool);
    if (rc == 0 && r->finfo.mtime > r->mtime)
	r->mtime = r->finfo.mtime;

    if ((dp = opendir(directory)) == NULL)
	return;

    for ( ; readdir_r(dp, entry, &res) == 0 && res != NULL; ) {
	char *file;

	/* no current/parent dir or hidden file except .DAV */
	if (entry->d_name[0] == '.' && strcmp(entry->d_name, ".DAV") != 0)
	    continue;

	file = apr_pstrcat(pool, directory, entry->d_name, NULL);
	rc = apr_stat(&r->finfo, file, APR_FINFO_MIN, pool);
	if (rc != 0)
	    continue;

	if (r->finfo.filetype == APR_DIR) {
	    if (recur < MAX_RECURSION) {
		file = apr_pstrcat(pool, file, "/", NULL);
		dav_acl_last_mtime(file, r, pool, ++recur);
	    }
	}
	else {
	    if (r->finfo.mtime > r->mtime)
	        r->mtime = r->finfo.mtime;
	}
    }
    closedir(dp);
}
