/* 
 *  FIPS 186-2 Pseudo-Random Number Generator
 *  Copyright (C) 2003 Mondru AB.
 * 
 *  Available under GPL or BSD license as described below.
 *
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 * 
 *  As an alternative to the GNU General Public License Version 2 the
 *  content may also be used under the license conditions described
 *  below:
 * 
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 * 
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 * 
 *  3. The name(s) of the authors of this software must not be used to
 *     endorse or promote products derived from this software without
 *     prior written permission. 

 *  THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 *  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 *  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 *  AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 *  OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * 
 *  The initial developer of the original code is
 *  Jens Jakobsen <jj@openggsn.org>
 * 
 *  Contributor(s):
 * 
 */

#ifndef _FIPS_H
#define _FIPS_H

void fips186_2_prng(unsigned char *XKEY, int XKEYlen, 
		    unsigned char *XSEEDj, int xseedjlen,
		    unsigned char *x, int xlen);

#endif  /* !_FIPS_H */
