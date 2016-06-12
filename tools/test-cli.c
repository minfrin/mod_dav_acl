/**
 *
 * Copyright (C) 2007 Nokia Corporation.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include <curl/curl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <getopt.h>
#include <sysexits.h>

static int verbose = 0;

typedef struct _header_s
{
    char *pch;
    size_t size;
} header_cb_t;

static size_t write_header_response(void *ptr, size_t size,
                                    size_t nmemb, void *data)
{
    header_cb_t *h = data;
    size_t realsize = size * nmemb;

    h->pch = realloc(h->pch, h->size + realsize + 1);
    if (h->pch) {
	memcpy(&h->pch[h->size], ptr, realsize);
	h->size += realsize;
	h->pch[h->size] = 0;
    }
    return nmemb;
}

static size_t write_response(void *ptr, size_t size,
                             size_t nmemb, void *data)
{
    FILE *writehere = data;

    return fwrite(ptr, size, nmemb, writehere);
}

static char util_esc(char ch)
{
    return ch < 10 ? ch + '0': ch - 10 + 'A';
}

/** escape uri and allocate result */
static char *escape_uri(char const *pcsz)
{
    if (pcsz == NULL || pcsz[0] == '\0')
	return NULL;
    {
	char *ret, *pch = malloc(strlen(pcsz) * 3 + 1);

	for (ret = pch; pcsz[0]; pcsz++) {
	    unsigned char ch = pcsz[0];

	    if (ch <= ' ' || ch >= '\177' || strchr ("\"[];\%", ch) != NULL) {
		*pch++ = '%';
		*pch++ = util_esc(ch >> 4);
		*pch++ = util_esc(ch & 0xf);
	    } else {
		*pch++ = ch;
	    }
	}
	*pch = 0;

	return ret;
     }
}

static void usage()
{
    fprintf(stdout,
	"acl-test-cli [OPTIONS] R-URI\n\n"
	"OPTIONS:\n"
	"  -v verbose printing\n"
	"  -A <user-agent>\n"
	"  -T <upload file>\n"
	"  -o <output file>\n"
	"  -u <username:password>\n"
	"  -i <If-Match>\n"
	"  -n <If-None-Match>\n"
	"  -e <Etag response file>\n"
	"  -s <store timing results to this filename>\n"
	"  -d <Depth>\n"
	"  -X <header>\n"
	"  -t <dump return status code to file>\n"
	"  -a <Accept>\n"
	"  -c <Content-Type>\n"
	"  -m <method> (GET, PUT, DELETE), GET default\n"
	"  -r <expected result code(s)> (comma separated, 200 default)\n\n"
	"R-URI (will be percent-encoded)\n\n"
	"returns 0 if succeeds, 1 for severe errors and "
	"76 for an error from libcurl\n");
}


int main(int argc, char **argv)
{
    CURL *curl;
    CURLcode res;
    FILE *hd_src = NULL, *hd_dest = NULL;
    int opt;
    long rc = EXIT_FAILURE;
    char *url = NULL;
    struct curl_slist *list = NULL;
    header_cb_t h[1] = { { 0 } };
    const char *user_agent = "acl-test-client";
    const char *input_file = NULL;
    const char *user = NULL;
    const char *etag = NULL;
    const char *method = "get";
    const char *ret_code = "200";
    const char *stored_file = NULL;
    const char *result_file = NULL;
    const char *status_file = NULL;
    char error_str[CURL_ERROR_SIZE + 1] = "";
    GTimer *timer;

    static const struct option longopts[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 1 },
	{ NULL, 0, NULL, 0 } };

    curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
    curl = curl_easy_init();

    if (curl == NULL) {
	fprintf(stderr, "libcurl could not be initialized !");
	return EXIT_FAILURE;
    }

    while ((opt = getopt_long(argc, argv, "A:T:u:d:s:i:n:X:e:a:o:c:m:r:t:hv",
				longopts, NULL)) != -1)
    switch (opt) {
    case 1:
	fprintf(stdout, "acl-test-cli version " VERSION "\n");
	return EXIT_SUCCESS;

    case '?':
	usage();
	return EXIT_FAILURE;

    case 'h':
	usage();
	return EXIT_SUCCESS;

    case 'o':
	stored_file = optarg;
	break;

    case 'X':
	list = curl_slist_append(list, optarg);
	break;

    case 'A':
	user_agent = optarg;
	break;

    case 'T':
	input_file = optarg;
	break;

    case 'u':
	user = optarg;
	break;

    case 'v':
	verbose = TRUE;
	break;

    case 'd':
	{
	    char *pch = g_strdup_printf("Depth: %s", optarg);
	    list = curl_slist_append(list, pch);
	    g_free(pch);
	}
	break;

    case 'i':
	{
	    char *pch;

	    if (strcmp(optarg, "*"))
		pch = g_strdup_printf("If-Match: \"%s\"", optarg);
	    else
		pch = g_strdup_printf("If-Match: *");

	    list = curl_slist_append(list, pch);
	    g_free(pch);
	}
	break;

    case 'n':
	{
	    char *pch;

	    if (strcmp(optarg, "*"))
		pch = g_strdup_printf("If-None-Match: \"%s\"", optarg);
	    else
		pch = g_strdup_printf("If-None-Match: *");

	    list = curl_slist_append(list, pch);
	    g_free(pch);
	}
	break;

    case 'e':
	etag = optarg;
	break;

    case 'a':
	{
	    char *pch = g_strdup_printf("Accept: %s", optarg);
	    list = curl_slist_append(list, pch);
	    g_free(pch);
	}
	break;

    case 'c':
	{
	    char *pch = g_strdup_printf("Content-Type: %s", optarg);
	    list = curl_slist_append(list, pch);
	    g_free(pch);
	}
	break;

    case 'm':
	method = optarg;
	break;

    case 's':
	result_file = optarg;
	break;

    case 't':
	status_file = optarg;
	break;

    case 'r':
	ret_code = optarg;
	break;
    }

    if (argc < 2) {
	usage();
	return EXIT_FAILURE;
    }

    url = escape_uri(argv[argc - 1]);

    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    if (verbose)
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    //curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    if (user_agent)
	curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent);

    if (stored_file) {
	hd_dest = fopen(stored_file, "w");

	if (hd_dest == NULL) {
	    fprintf(stderr, "Could not open output file '%s'\n", stored_file);
	    return EXIT_FAILURE;
	}
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, hd_dest);
    }

    if (input_file) {
	struct stat file_info;

	if (stat(input_file, &file_info) < 0) {
	    fprintf(stderr, "Could not open input file '%s' for put\n",
			     input_file);
	    return EXIT_FAILURE;
	}

	hd_src = fopen(input_file, "r");

	if (hd_src == NULL) {
	    fprintf(stderr, "Could not open file for %s for upload\n",
			    input_file);
	    return EXIT_FAILURE;
	}
	/* enable uploading */
	curl_easy_setopt(curl, CURLOPT_UPLOAD, TRUE);

	/* now specify which file to upload */
	curl_easy_setopt(curl, CURLOPT_READDATA, hd_src);

	curl_easy_setopt(curl, CURLOPT_INFILESIZE, file_info.st_size);
    }

    if (list)
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

    if (strcasecmp(method, "get") == 0) {
	;
    } 
    else if (strcasecmp(method, "put") == 0) {
	if (input_file == NULL) {
	    fprintf(stderr, "No input file defined for put\n");
	    return EXIT_FAILURE;
	}
	/* HTTP PUT */
	curl_easy_setopt(curl, CURLOPT_UPLOAD, TRUE);
    }
    else {
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);

    if (user) {
	curl_easy_setopt(curl, CURLOPT_USERPWD, user);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
    }

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_header_response);
    curl_easy_setopt(curl, CURLOPT_WRITEHEADER, (void *) h);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_str);

    timer = g_timer_new();

    g_timer_start(timer);

    res = curl_easy_perform(curl);
    {
	gdouble el;

	g_timer_stop(timer);

	el = g_timer_elapsed(timer, NULL);

	if (result_file) {
	    FILE *hf = fopen(result_file, "a");

	    fprintf(hf, "%s\t%1.1f %s\n", user_agent,
		    el > 0.001 ? el * 1000 : el * 1e6,
		    el > 0.001 ? "ms": "us");

	    fclose(hf);
	}
    }
    g_timer_destroy(timer);

    if (res != CURLE_OK) {
	fprintf(stderr, "Curl perform failed: %d/%s\n", res, error_str);
	return EXIT_FAILURE;
    }

    if (h->pch == NULL) {
	fprintf(stderr, "No received response headers from the server\n");
	return EXIT_FAILURE;
    }

    if (verbose && h->pch)
	printf("%s", h->pch);
    {
	char *p = h->pch;

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rc);

	if (verbose)
	    printf("Request return code %ld\n", rc);

	if (status_file) {
	    FILE *s = fopen(status_file, "w");

	    if (s == NULL) {
		fprintf(stderr, "Could not write status result to file '%s', "
				"error:'%s'\n", status_file, strerror(errno));
		return EXIT_FAILURE;
	    }
	    fprintf(s, "%ld", rc);
	    fflush(s);
	    fclose(s);
	}

	if (etag && rc < 400) {
	    FILE *s;

	    p = strstr(p, "ETag:");

	    if (p == NULL) {
		fprintf(stderr, "Could not locate ETag header\n");
		return EXIT_FAILURE;
	    }
	    p += 5;

	    for ( ; *p && *p != '"'; p++)
		;

	    if (*p == 0) {
		fprintf(stderr, "No quote in ETag %s\n", p);
		return EXIT_FAILURE;
	    }

	    s = fopen(etag, "w");
	    if (s == NULL) {
		fprintf(stderr, "Could not write ETag result to file '%s', "
				"error:'%s'\n", etag, strerror(errno));
		return EXIT_FAILURE;
	    }

	    if (verbose)
		printf("ETag: ");

	    for (p++; *p && *p != '"'; p++) {
		if (fwrite(p, 1, 1, s))
		    fprintf(stderr, "ETag write error:'%s'\n", strerror(errno));

		if (verbose)
		    fputc(*p, stdout);
	    }
	    fflush(s);
	    fclose(s);

	    if (verbose)
		fputc('\n', stdout);
	}
    }

    for ( ;; ) {
	char *p = strchr(ret_code, ',');

	if (atoi(ret_code) == rc) {
	    rc = EXIT_SUCCESS;
	    break;
	}
	if (p == NULL)
	    break;

	ret_code = p + 1;
    }
    free(h->pch), h->pch = NULL;

    if (hd_src)
	fclose(hd_src);

    if (hd_dest)
	fclose(hd_dest);

    curl_easy_cleanup(curl);
    curl_slist_free_all(list);

    curl_global_cleanup();
    free(url);

    if (verbose)
	printf("process %s, return code %ld\n",
		rc == EXIT_SUCCESS ? "succeeded" : "failed", rc);

    if (result_file && rc) {
	FILE *hf = fopen(result_file, "a");
	fprintf(hf, "\tError rc:%ld\n", rc);
	fclose(hf);
    }

    return rc == EXIT_SUCCESS ? EXIT_SUCCESS : EX_PROTOCOL;
}
