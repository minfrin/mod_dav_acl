/**
 * This is part of a mod_dav_acl library.
 * acl_liveprops.c: mod_dav_acl live property provider functions
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

#include <sys/types.h>

#include <httpd.h>
#include <libxml/tree.h>

#include <mod_dav.h>

#include "mod_dav_acl.h"
#include "apr_strings.h"

/*
** The namespace URIs that we use. This list and the enumeration must
** stay in sync.
*/
static const char * const dav_acl_namespace_uris[] =
{
    "DAV:",
    NULL        /* sentinel */
};

enum {
    DAV_ACL_NAMESPACE_URI_DAV = 0  /* the DAV: namespace URI */
};

#define ACL_RO_PROP(name, enum_name) \
        { DAV_ACL_NAMESPACE_URI_DAV, name, ACL_PROPID_##enum_name, 0 }
#define ACL_RW_PROP(name, enum_name) \
        { DAV_ACL_NAMESPACE_URI_DAV, name, ACL_PROPID_##enum_name, 1 }

enum {
    ACL_PROPID_supported_privilege_set = 1,
    ACL_PROPID_current_user_privilege_set,
    ACL_PROPID_acl,
    ACL_PROPID_acl_restrictions,
    ACL_PROPID_inherited_acl_set,
    ACL_PROPID_principal_collection_set,
    ACL_PROPID_owner,
    ACL_PROPID_principal_url,
    ACL_PROPID_alternate_uri_set,
    ACL_PROPID_group_membership,
    ACL_PROPID_group_member_set,
    ACL_PROPID_group,
    ACL_PROPID_current_user_principal
};

static const dav_liveprop_spec dav_acl_props[] =
{
    ACL_RO_PROP("owner", owner),   /* could also be a writable resource,
                                    * now set by put or mkcol */
    ACL_RW_PROP("group", group),
    ACL_RO_PROP("supported-privilege-set", supported_privilege_set),
    ACL_RO_PROP("current-user-privilege-set", current_user_privilege_set),
    ACL_RO_PROP("acl", acl),
    ACL_RO_PROP("acl-restrictions", acl_restrictions),
    ACL_RO_PROP("inherited-acl-set", inherited_acl_set),
    ACL_RO_PROP("principal-collection-set", principal_collection_set),
    ACL_RO_PROP("principal-URL", principal_url),
    ACL_RO_PROP("alternate-URI-set", alternate_uri_set),
    ACL_RO_PROP("group-membership", group_membership),
    ACL_RW_PROP("group-member-set", group_member_set),
    ACL_RO_PROP("current-user-principal", current_user_principal),
    { 0 } /* sentinel */
};

const dav_hooks_liveprop dav_acl_hooks_liveprop;

static const dav_liveprop_group dav_acl_liveprop_group =
{
    dav_acl_props,
    dav_acl_namespace_uris,
    &dav_acl_hooks_liveprop
};

static xmlNodePtr add_supported(xmlNodePtr parent, xmlNsPtr ns,
                                const char *priv, int abstract,
                                const char *desc)
{
    xmlNodePtr ret = xmlNewChild(parent, ns,
                                 (const xmlChar *) "supported-privilege", NULL);
    xmlNodePtr cur = xmlNewChild(ret, ns, (const xmlChar *) "privilege", NULL);
    xmlNewChild(cur, ns, (const xmlChar *) priv, NULL);
    if (abstract)
        xmlNewChild(ret, ns, (const xmlChar *) "abstract", NULL);
    xmlNewChild(ret, ns, (const xmlChar *) "description",
                (const xmlChar *) desc);
    return ret;
}

static dav_prop_insert dav_acl_insert_prop(const dav_resource *resource,
                                           int propid, dav_prop_insert what,
                                           apr_text_header *phdr)
{
    const char *value = NULL;
    const char *s = NULL;
    apr_pool_t *p = resource->pool;
    const dav_liveprop_spec *info;
    int global_ns, rc;

    if (!resource->exists)
        return DAV_PROP_INSERT_NOTDEF;

    /* ### we may want to respond to DAV_PROPID_resourcetype for PRIVATE
       ### resources. need to think on "proper" interaction with mod_dav */

    switch (propid) {
    case ACL_PROPID_acl:
        if (what == DAV_PROP_INSERT_VALUE) {
            /* request_rec *r = resource->hooks->get_request_rec(resource) */;
            xmlBufferPtr buf = NULL;
            const char *pch = NULL;
            xmlDocPtr doc;
            xmlNodePtr node;

            rc = dav_acl_get_acl(resource, &pch, &rc);
            if (rc < 0)
                return DAV_PROP_INSERT_NOTDEF;

            doc = xmlParseMemory(pch, rc);
            node = doc && doc->children ? doc->children : NULL;

            buf = xmlBufferCreate();
            xmlNodeDump(buf, doc, node, 0, 1);
            xmlFreeDoc(doc);

            apr_text_append(p, phdr, apr_psprintf (p, "%s" DEBUG_CR,
                            buf->content));
            /* we inserted whatever was asked for */
            xmlBufferFree(buf);
            return what;
        }
        break;

    case ACL_PROPID_acl_restrictions:
        value = "<D:required-principal>"
                "<D:authenticated/>"
                "<D:unauthenticated/>"
                "<D:self/>"
                "<D:all/>"
                "<D:href/>"
                "<D:property><D:owner/></D:property>"
                "<D:property><D:group/></D:property>"
                "</D:required-principal>";
        break;

    case ACL_PROPID_supported_privilege_set:
        if (what == DAV_PROP_INSERT_VALUE) {
            xmlBufferPtr buf = NULL;

            xmlDocPtr doc = xmlNewDoc((const xmlChar *) XML_VERSION);
            xmlNsPtr ns;
            xmlNodePtr cur, child, node;
            int acl, cups;

            dav_acl_get_aggregated(resource, &acl, &cups);

            doc->children = xmlNewDocNode(doc, NULL,
                                          (const xmlChar *) "root", NULL);
            xmlSetNs(doc->children,
                     ns = xmlNewNs(doc->children, (const xmlChar *) "DAV:",
                     (const xmlChar *) "D"));

            node = xmlNewChild(doc->children, ns,
                                (const xmlChar *) "supported-privilege-set",
                                NULL);

            cur = add_supported(node, ns, "all", 0, "All privileges");

            child = add_supported(cur, ns, "read", 0, "Read");

            add_supported(acl ? child : cur, ns, "read-acl", 0, "Read ACL");

            add_supported(cups ? child : cur, ns,
                          "read-current-user-privilege-set", 0,
                          "Read Current User");

            child = add_supported(cur, ns, "write", 0, "Write");

            add_supported(child, ns, "write-acl", 0, "Write ACL");
            add_supported(child, ns, "write-content", 0, "Write content");
            add_supported(child, ns, "write-properties", 0,
                                                        "Write properties");

            if (resource->collection) {
                add_supported(child, ns, "bind", 0, "Create a collection");
                add_supported(child, ns, "unbind", 0, "Remove a collection");
            }
            add_supported(cur, ns, "unlock", 0, "Unlock");

            buf = xmlBufferCreate();
            xmlNodeDump(buf, doc, node, 0, 1);
            xmlFreeDoc(doc);

            apr_text_append(p, phdr, apr_psprintf(p, "%s" DEBUG_CR,
                                                        buf->content));
            /* we inserted whatever was asked for */
            xmlBufferFree(buf);
            return what;
        }
        break;

    case ACL_PROPID_group_membership:
        value = dav_acl_get_group_membership(resource);
        if (value == NULL)
            return DAV_PROP_INSERT_NOTDEF;
        break;

    case ACL_PROPID_owner:
        value = dav_acl_get_owner(resource);
        if (value == NULL)
            return DAV_PROP_INSERT_NOTDEF;
        break;

    case ACL_PROPID_alternate_uri_set:
        value = "";  /* may be empty */
        break;

    case ACL_PROPID_inherited_acl_set:
        value = "";  /* not supported because of complexity... */
        break;

    case ACL_PROPID_current_user_privilege_set:
        value = dav_acl_get_privs(resource);
        break;

    case ACL_PROPID_principal_collection_set:
        {
            request_rec *r = resource->hooks->get_request_rec(resource);

            const char *pcsz = dav_acl_get_principals(r);

            value = apr_psprintf(p, "<D:href>%s/</D:href>", pcsz ? pcsz : "");
        }
        break;

    case ACL_PROPID_current_user_principal:
        value = dav_acl_get_auth_principal(resource);
        if (value)
            value = apr_psprintf(p, "<D:href>%s</D:href>", value);
        else
            value = "<D:unauthenticated/>";
        break;

    default:
        /* ### what the heck was this property? */
        return DAV_PROP_INSERT_NOTDEF;
    }

    /* assert: value != NULL */

    /* get the information and global NS index for the property */
    global_ns = dav_get_liveprop_info(propid, &dav_acl_liveprop_group, &info);

    /* assert: info != NULL && info->name != NULL */

    if (what == DAV_PROP_INSERT_VALUE)
        s = apr_psprintf(p, "<lp%d:%s>%s</lp%d:%s>" DEBUG_CR,
                         global_ns, info->name, value, global_ns, info->name);
    else if (what == DAV_PROP_INSERT_NAME)
        s = apr_psprintf(p, "<lp%d:%s/>" DEBUG_CR, global_ns, info->name);
    else
        /* assert: what == DAV_PROP_INSERT_SUPPORTED */
        s = apr_psprintf(p,
                         "<D:supported-live-property D:name=\"%s\" "
                         "D:namespace=\"%s\"/>" DEBUG_CR,
                         info->name, dav_acl_namespace_uris[info->ns]);

    apr_text_append(p, phdr, s);

    /* we inserted whatever was asked for */
    return what;
}

static int dav_acl_is_writable(const dav_resource *resource, int propid)
{
    const dav_liveprop_spec *info;

    dav_get_liveprop_info(propid, &dav_acl_liveprop_group, &info);

    return info->is_writable;
}

static char *acl_get_elem_text(apr_pool_t *p, const apr_text *t)
{
    char *pch = NULL;

    for ( ; t; t = t->next)
        pch = apr_pstrcat(p, pch ? pch : "", t->text, NULL);

    return pch;
}

static dav_error *dav_acl_patch_validate(const dav_resource *resource,
                                         const apr_xml_elem *elem,
                                         int operation, void **context,
                                         int *defer_to_dead)
{
    dav_elem_private *priv = elem->priv;

    switch (priv->propid) {
    case ACL_PROPID_group:
    case ACL_PROPID_group_member_set:
        /* actually a dead property, but defined as alive to have
         * this callback for proppatch */
        *defer_to_dead = TRUE;

        if (operation == DAV_PROP_OP_SET) {
            request_rec *r = resource->hooks->get_request_rec(resource);
            const char *pch = dav_acl_get_principals(r);
            apr_xml_elem *child = elem->first_child;

            for ( ; child; child = child->next) {
                if (strcmp(child->name, "href") == 0) {
                    const char *
                        href = acl_get_elem_text(resource->pool,
                                                 child->first_cdata.first);

                    if (pch && (!href || strncmp(href, pch, strlen (pch)) != 0))
                        return dav_new_error(resource->pool, HTTP_CONFLICT, 0, APR_SUCCESS,
                                             "The principal uri path not "
                                             "supported");
                }
            }
        }
        break;

    default:
        break;
    }

    return NULL;
}

static dav_error *dav_acl_patch_exec(const dav_resource *resource,
                                     const apr_xml_elem *elem,
                                     int operation, void *context,
                                     dav_liveprop_rollback **rollback_ctx)
{
    /* NOTE: this function will not be called unless/until we have
       modifiable (writable) live properties. */
    return NULL;
}

static void dav_acl_patch_commit(const dav_resource *resource, int operation,
                                 void *context,
                                 dav_liveprop_rollback *rollback_ctx)
{
    /* NOTE: this function will not be called unless/until we have
       modifiable (writable) live properties. */
}

static dav_error *dav_acl_patch_rollback(const dav_resource *resource,
                                         int operation, void *context,
                                         dav_liveprop_rollback *rollback_ctx)
{
    /* NOTE: this function will not be called unless/until we have
       modifiable (writable) live properties. */
    return NULL;
}

const dav_hooks_liveprop dav_acl_hooks_liveprop = {
    dav_acl_insert_prop,
    dav_acl_is_writable,
    dav_acl_namespace_uris,
    dav_acl_patch_validate,
    dav_acl_patch_exec,
    dav_acl_patch_commit,
    dav_acl_patch_rollback,
};

void dav_acl_gather_propsets(apr_array_header_t *uris)
{
}

int dav_acl_find_liveprop(const dav_resource *resource,
                          const char *ns_uri, const char *name,
                          const dav_hooks_liveprop **hooks)
{
    /* don't try to find any liveprops if this isn't "our" resource
     * if (resource->hooks != &dav_acl_hooks_repos)
     *   return 0;
     */
    return dav_do_find_liveprop(ns_uri, name, &dav_acl_liveprop_group, hooks);
}

void dav_acl_register_props(apr_pool_t *p)
{
    /* register the namespace URIs */
    dav_register_liveprop_group(p, &dav_acl_liveprop_group);
}
