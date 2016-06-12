bin_PROGRAMS = acl-xpath acl-test-cli

bin_SCRIPTS = acl-principals

acl_xpath_SOURCES = xpath.c
acl_xpath_CFLAGS = @DEPS_LIBXML_CFLAGS@
acl_xpath_LDADD = @DEPS_LIBXML_LIBS@

acl_test_cli_CFLAGS = $(DEPS_CURL_CFLAGS)
acl_test_cli_LDADD = $(DEPS_CURL_LIBS)
acl_test_cli_SOURCES = test-cli.c
