##
## Toplevel Makefile.am
##

INCLUDES	= @GLIB_CFLAGS@

sbin_PROGRAMS	= itd

itd_SOURCES	= \
	elist.h scsi_cmd_codes.h iscsiutil.h iscsi.h parameters.h target.h \
	main.c iscsi.c target.c util.c parameters.c
itd_LDADD	= @GLIB_LIBS@ @CRYPTO_LIBS@ @EVENT_LIBS@ @HAIL_LIBS@

EXTRA_DIST	= autogen.sh

