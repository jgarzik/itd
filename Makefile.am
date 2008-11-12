##
## Toplevel Makefile.am
##

INCLUDES	= @GNET_CFLAGS@

sbin_PROGRAMS	= itd

itd_SOURCES	= \
compat.h  defs.h    iscsiutil.h   storage.h \
device.h  iscsi.h	 parameters.h  target.h \
	main.c iscsi.c target.c util.c parameters.c netmask.c strlcpy.c
itd_LDADD	= @GNET_LIBS@ @CRYPTO_LIBS@

EXTRA_DIST	= autogen.sh

