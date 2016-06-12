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
#ifndef _ACL_LIVEPROPS_H_
#define _ACL_LIVEPROPS_H_

void dav_acl_gather_propsets(apr_array_header_t *uris);
int dav_acl_find_liveprop(const dav_resource *resource, const char *ns_uri,
                          const char *name, const dav_hooks_liveprop **hooks);
void dav_acl_insert_all_liveprops(request_rec *r, const dav_resource *resource,
                                  dav_prop_insert what, apr_text_header *phdr);

/* register our live property URIs with mod_dav. */
void dav_acl_register_props(apr_pool_t *p);

#endif /* _ACL_LIVEPROPS_H_ */
