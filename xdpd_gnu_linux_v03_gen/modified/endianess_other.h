/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _ENDIAN_OTHER_CONVERSION_H
#define _ENDIAN_OTHER_CONVERSION_H       1

#include <endian.h>

/* Conversion interfaces.  */
# include <byteswap.h>

#  define be8toh(x) (x)
#  define htobe8(x) (x)

#endif /* _ENDIAN_OTHER_CONVERSION_H */
