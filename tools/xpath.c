/**
 * This is part of a mod_dav_acl library.
 * tool to dump node content from an xml-file.
 * selections based on xpath expression.
 *
 * Copyright (C) 2011 Nokia Corporation.
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

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

static void usage()
{
    fprintf(stdout,
	"acl-xpath [OPTIONS] -d <xml-file> -e <xpath-expr>\n\n"
	"OPTIONS:\n"
	"    -n <known-ns-list>\n"
	"    -s <sub-xpath-expr>\n"
	"where <known-ns-list> is a list of known namespaces "
	"with 'prefix1=href1 prefix2=href2 ...' format.\n\n"
	"<sub-xpath-expr> searches are done relative to "
        "<xpath-expr> located nodes.\n\n"
	"Multiple nodes may be combined with the union '|' character.\n");
}

static int register_namespaces(xmlXPathContext *ctxt, char *list)
{
    char *prefix, *href, *next = list;

    while (next != NULL) {
	while (*next == ' ')
	    next++;

	if (*next == '\0')
	    break;

	prefix = next;
	next = strchr(next, '=');
	if (next == NULL) {
	    fprintf(stderr, "Error: invalid namespaces list format\n");
	    return -1;
	}
	*next++ = '\0';

	href = next;
	next = strchr(next, ' ');
	if (next != NULL)
	    *next++ = '\0';

	if (xmlXPathRegisterNs(ctxt, (xmlChar *) prefix,
					(xmlChar *) href) != 0) {
	    fprintf(stderr, "Error: unable to register namespace '%s:%s'\n",
		    prefix, href);
	    return -1;
	}
    }

    return 0;
}

void dump_xpath_nodes(xmlNodeSet *nodes, xmlXPathContext *ctxt,
                      char *sub_expr, FILE *output)
{
    xmlNode *cur;
    int i, count = nodes ? nodes->nodeNr : 0;

    for (i = 0; i < count; ++i) {
	cur = nodes->nodeTab[i];

	if (cur->type == XML_NAMESPACE_DECL) {
	    xmlNs *ns = (xmlNs *) cur;

	    cur = (xmlNode *) ns->next;

	    if (cur->ns)
		fprintf(output, "\"%s\"=\"%s\" for node %s:%s",
			ns->prefix, ns->href, cur->ns->href, cur->name);
	    else
		fprintf(output, "\"%s\"=\"%s\" for node %s",
			ns->prefix, ns->href, cur->name);
	    cur = nodes->nodeTab[i];
	}
	else if (cur->type == XML_ELEMENT_NODE || cur->type == XML_TEXT_NODE) {
	    xmlBuffer *buf = xmlBufferCreate();
	    xmlNodeDump(buf, cur->doc, cur, 0, 1);
	    fprintf(output, "%s", buf->content);
	    xmlBufferFree(buf);
	}
	else if (cur->type == XML_ATTRIBUTE_NODE) {
	    xmlBuffer *buf = xmlBufferCreate();
	    xmlAttr *attr = (xmlAttrPtr) cur;
	    xmlNodeDump(buf, attr->doc, attr->children, 0, 0);
	    fprintf(output, "%s", buf->content);
	    xmlBufferFree(buf);
	}
	else {
	    fprintf(output, "\"%s\": type %d\t", cur->name, cur->type);
	}

	if (sub_expr) {
	    xmlXPathObject *obj;

	    ctxt->node = cur;

	    obj = xmlXPathEvalExpression((xmlChar *) sub_expr, ctxt);
	    if (obj == NULL) {
		fprintf (stderr, "Error: unable to evaluate xpath expression "
				 "'%s'\n", sub_expr);
	    }
	    else {
		fprintf(output, "\t");
		dump_xpath_nodes(obj->nodesetval, NULL, NULL, stdout);
		xmlXPathFreeObject(obj);
	    }
	    ctxt->node = xmlDocGetRootElement(cur->doc);
	}
	if (ctxt)
	    fprintf(output, "\n");
	else if (i + 1 < count)
	    fprintf(output, "\t");
    }
}

static int eval_xpath(const char *filename, const char *expr,
                      char *sub_expr, char *ns)
{
    xmlDoc *doc;
    xmlXPathContext *ctxt;
    xmlXPathObject *obj;

    doc = xmlReadFile(filename, NULL, XML_PARSE_NOWARNING);
    if (doc == NULL) {
	fprintf(stderr, "Error: unable to parse file '%s'\n", filename);
	return -1;
    }

    ctxt = xmlXPathNewContext(doc);
    if (ctxt == NULL) {
	fprintf(stderr, "Error: unable to create new XPath context\n");
	xmlFreeDoc(doc);
	return -1;
    }

    if (ns != NULL && register_namespaces(ctxt, ns) < 0) {
	fprintf(stderr, "Error: failed to register namespaces '%s'\n", ns);
	xmlXPathFreeContext(ctxt);
	xmlFreeDoc(doc);
	return -1;
    }

    obj = xmlXPathEvalExpression((xmlChar *) expr, ctxt);
    if (obj == NULL) {
	fprintf(stderr, "Error: unable to evaluate expression '%s'\n", expr);
	xmlXPathFreeContext(ctxt);
	xmlFreeDoc(doc);
	return -1;
    }

    dump_xpath_nodes(obj->nodesetval, ctxt, sub_expr, stdout);

    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);

    return 0;
}

int main(int argc, char **argv)
{
    int opt;
    char *filename = NULL, *expr = NULL, *ns_list = NULL, *sub_expr = NULL;

    static const struct option longopts[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 1 },
	{ NULL, 0, NULL, 0 } };

    while ((opt = getopt_long(argc, argv, "d:e:n:s:vh?", longopts, NULL)) != -1)
    switch (opt) {
    case 1:
	fprintf(stdout, "acl-xpath version " VERSION "\n");
	return EXIT_SUCCESS;

    case 'h':
	usage();
	return EXIT_SUCCESS;

    case '?':
	usage();
	return EXIT_FAILURE;

    case 'd':
	filename = optarg;
	break;

    case 'e':
	expr = optarg;
	break;

    case 'n':
	ns_list = optarg;
	break;

    case 's':
	sub_expr = optarg;
	break;
    }

    if (filename == NULL || expr == NULL) {
	usage();
	return EXIT_FAILURE;
    }

    xmlInitParser();

    if (eval_xpath(filename, expr, sub_expr, ns_list) < 0) {
	usage();
	return EXIT_FAILURE;
    }

    xmlCleanupParser();

    return EXIT_SUCCESS;
}

