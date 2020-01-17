#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([vanityETHMPI], [1.0], [ethereumdreamer@gmail.com])
AM_INIT_AUTOMAKE(vanityETHMPI, 1.0)
AM_INIT_AUTOMAKE([subdir-objects])
AC_OUTPUT(Makefile src/Makefile)
AC_CONFIG_SRCDIR([src/vanityETHMPI.c])
AC_CONFIG_HEADERS([config.h])

openssl_libs="-lssl -lcrypto"
openssl_inc=
# Checks for packages
#PKG_CHECK_MODULES([openssl], [openssl >= 1.0])
AC_ARG_WITH(openssl,
[AS_HELP_STRING([--with-openssl=PATH],
        [specify prefix directory for the installed openssl package.
         Equivalent to --with-openssl-include=PATH/include
         plus --with-openssl-lib=PATH/lib])])
AC_ARG_WITH(openssl-include,
[AS_HELP_STRING([--with-openssl-include=PATH],
        [specify directory for installed openssl include files])])
AC_ARG_WITH(openssl-lib,
[AS_HELP_STRING([--with-openssl-lib=PATH],
        [specify directory for the installed openssl library])])

ssl_check=""
ssl_good=0
if test "x$with_openssl" != x; then
  openssl_libs="-L$with_openssl/lib $openssl_libs"
  openssl_inc="-I$with_openssl/include $openssl_inc"
  ssl_check=$($with_openssl/bin/openssl ecparam -list_curves | grep "secp256k1" | awk '{ print $1 }')
  if test "x$ssl_check" != xsecp256k1; then
    AC_MSG_ERROR("Provided openssl package does not support secp256k1 curve")
  fi
  ssl_good=1
fi
if test "x$with_openssl_include" != x; then
  openssl_inc="-I$with_openssl_include $openssl_inc"
fi
if test "x$with_openssl_lib" != x; then
  openssl_libs="-L$with_openssl_lib $openssl_libs"
fi

if test "x$ssl_good" = x0; then
  AC_CHECK_PROG([openssl_in_path], [openssl], yes)
  if test "x$openssl_in_path" != xyes; then
    AC_MSG_ERROR([Building vanityETHMPI requires openssl to be installed.
            Try the --with-openssl to specify install prefix if it was installed to a
            non-standard path.])
  fi
  ssl_check=$(openssl ecparam -list_curves | grep "secp256k1" | awk '{ print $1 }')
  if test "x$ssl_check" != xsecp256k1; then
    AC_MSG_ERROR(Installed openssl package does not support secp256k1 curve)
  fi
fi

AC_SUBST([openssl_libs],[$openssl_libs])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB(mpi,MPI_Init,[HAVE_LIBMPI=1],[HAVE_LIBMPI=0])
AM_CONDITIONAL([USE_MPI], [test "x$HAVE_LIBMPI" = x1])

# Checks for header files.
AC_CHECK_HEADERS([limits.h stddef.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strchr strtol])

AS_IF([test "x$HAVE_LIBMPI" = x0], AC_MSG_WARN("MPI NOT FOUND - only serial version will be built"))

AC_OUTPUT
