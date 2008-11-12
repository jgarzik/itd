##
## Toplevel Makefile.am
##

INCLUDES	= @GNET_CFLAGS@

sbin_PROGRAMS	= itd

itd_SOURCES	= \
	iscsiutil.h iscsi.h parameters.h target.h	\
	main.c iscsi.c target.c util.c parameters.c netmask.c strlcpy.c
itd_LDADD	= @GNET_LIBS@ @CRYPTO_LIBS@

EXTRA_DIST	= autogen.sh

