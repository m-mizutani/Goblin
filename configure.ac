#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT(goblin, 0.2, mizutani@sfc.wide.ad.jp)
AM_INIT_AUTOMAKE(goblin, 0.2, mizutani@sfc.wide.ad.jp)

AC_CONFIG_FILES([Makefile
                 src/Makefile])

AC_CHECK_HEADERS([stdlib.h])
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for programs.
AC_PROG_RANLIB
AC_PROG_CC

CFLAGS="$CFLAGS -Wall"
	      

# Checks for libraries.

######################################################################
# libpcap
######################################################################

AC_ARG_WITH(libpcap,
    [  --with-libpcap=DIR        support libpcap],
    [ with_libpcap="$withval" ],
    [ with_libpcap=$with_libpcap_default ])


libpcap_default_directory="/usr /usr/local /usr/pkg ${prefix}"
libpcap_fail="no"
libpcap_dir="$libpcap_default_directory"
  
if test "$with_libpcap" != "no"; then
  AC_MSG_CHECKING(for libpcap)
  if test "$with_libpcap" = "yes"; then
    libpcap_dir="$libpcap_default_directory";
  elif test -d "$withval"; then
    libpcap_dir="$withval";
  elif test "$with_libpcap" != ""; then
    AC_MSG_ERROR("Invalid Libpcap directory: $with_libpcap")
  fi

  tmp=""
  LIBPCAP_DIR="";
  for i in $libpcap_dir; do
    if test -r $i/include/pcap/pcap.h; then
      LIBPCAP_DIR="$i"
      LIBPCAP_INC_DIR=$i/include/libpcap
    elif test -r $i/include/pcap.h; then
      LIBPCAP_DIR="$i"
      LIBPCAP_INC_DIR=$i/include/
    fi
    tmp="$tmp $i/include/pcap/ $i/include/"
  done

  if test "$LIBPCAP_DIR" = ""; then
    AC_MSG_ERROR("Not found libpcap.h: $tmp")
  fi

  LIBPCAP_LIB_DIR=""
  for i in lib lib/libpcap; do
    tmp="$LIBPCAP_DIR/$i/libpcap.*"
     for j in $tmp; do
       if test -r "$j"; then
         LIBPCAP_LIB_DIR="$LIBPCAP_DIR/$i"
         break
       fi
     done
  done

  if test -z "$LIBPCAP_LIB_DIR"; then
    AC_MSG_ERROR("Not found libpcap.so*: $LIBPCAP_DIR/lib/ $LIBPCAP_DIR/lib/pcap/")
  fi

  AC_MSG_RESULT(yes)
  AC_DEFINE([WITH_LIBPCAP], [1], [With Libpcap])
  LDFLAGS="${LDFLAGS} -L${LIBPCAP_LIB_DIR}"
  CPPFLAGS="${CPPFLAGS} -I${LIBPCAP_INC_DIR}"
  AC_DEFINE_UNQUOTED(WITH_LIBPCAP, 1, support libpcap)
  if test "$enable_static" = "yes"; then
    LIBS="${LIBS} ${LIBPCAP_LIB_DIR}/libpcap.a"
  else
    LIBS="${LIBS} -lpcap"
  fi
fi



AC_OUTPUT
