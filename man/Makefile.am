man_MANS = acl-test-cli.1 acl-xpath.1 acl-principals.1
EXTRA_DIST = $(man_MANS)
MAINTAINERCLEANFILES = $(man_MANS)

acl-test-cli.1: $(top_srcdir)/tools/test-cli.c
	$(HELP2MAN) --name="ACL test client tool" ../tools/acl-test-cli -o $@

acl-xpath.1: $(top_srcdir)/tools/xpath.c
	$(HELP2MAN) --name="ACL xpath test tool" ../tools/acl-xpath -o $@

acl-principals.1: $(top_srcdir)/tools/acl-principals
	$(HELP2MAN) --name="ACL principal tool" ../tools/acl-principals -o $@
