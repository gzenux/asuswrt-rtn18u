/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Renames all zlib functions to have ssh prefix.
*/

#ifndef SSHZLIBRENAME_H
#define SSHZLIBRENAME_H

/* Define zlib to have ssh prefix, so we will not care if there is another zlib
   in the kernel */
#define deflateInit_            ssh_z_deflateInit_
#define deflate                 ssh_z_deflate
#define deflateEnd              ssh_z_deflateEnd
#define inflateInit_            ssh_z_inflateInit_
#define inflate                 ssh_z_inflate
#define inflateEnd              ssh_z_inflateEnd
#define deflateInit2_           ssh_z_deflateInit2_
#define deflateSetDictionary    ssh_z_deflateSetDictionary
#define deflateCopy             ssh_z_deflateCopy
#define deflateReset            ssh_z_deflateReset
#define deflateParams           ssh_z_deflateParams
#define inflateInit2_           ssh_z_inflateInit2_
#define inflateSetDictionary    ssh_z_inflateSetDictionary
#define inflateSync             ssh_z_inflateSync
#define inflateSyncPoint        ssh_z_inflateSyncPoint
#define inflateReset            ssh_z_inflateReset
#define compress                ssh_z_compress
#define compress2               ssh_z_compress2
#define uncompress              ssh_z_uncompress
#define adler32                 ssh_z_adler32
#define crc32                   ssh_z_crc32
#define get_crc_table           ssh_z_get_crc_table

#define Byte                    ssh_z_Byte
#define uInt                    ssh_z_uInt
#define uLong                   ssh_z_uLong
#define Bytef                   ssh_z_Bytef
#define charf                   ssh_z_charf
#define intf                    ssh_z_intf
#define uIntf                   ssh_z_uIntf
#define uLongf                  ssh_z_uLongf
#define voidpf                  ssh_z_voidpf
#define voidp                   ssh_z_voidp
#define _tr_align               ssh_z__tr_align
#define _tr_flush_block         ssh_z__tr_flush_block
#define _tr_init                ssh_z__tr_init
#define _tr_stored_block        ssh_z__tr_stored_block
#define _tr_tally               ssh_z__tr_tally
#define deflate_copyright       ssh_z_deflate_copyright
#define inflate_blocks          ssh_z_inflate_blocks
#define inflate_blocks_free     ssh_z_inflate_blocks_free
#define inflate_blocks_new      ssh_z_inflate_blocks_new
#define inflate_blocks_reset    ssh_z_inflate_blocks_reset
#define inflate_codes           ssh_z_inflate_codes
#define inflate_codes_free      ssh_z_inflate_codes_free
#define inflate_codes_new       ssh_z_inflate_codes_new
#define inflate_copyright       ssh_z_inflate_copyright
#define inflate_fast            ssh_z_inflate_fast
#define inflate_flush           ssh_z_inflate_flush
#define inflate_mask            ssh_z_inflate_mask
#define inflate_set_dictionary  ssh_z_inflate_set_dictionary
#define inflate_trees_bits      ssh_z_inflate_trees_bits
#define inflate_trees_dynamic   ssh_z_inflate_trees_dynamic
#define inflate_trees_fixed     ssh_z_inflate_trees_fixed
#define z_errmsg                ssh_z_z_errmsg
#define zlibVersion             ssh_z_zlibVersion

#define zError                  ssh_z_zError
#define inflate_blocks_sync_point       ssh_z_inflate_blocks_sync_point

#define zcalloc                 ssh_z_zcalloc
#define zcfree                  ssh_z_zcfree
#define _dist_code              ssh__dist_code
#define _length_code            ssh__length_code


#endif /* SSHZLIBRENAME_H */
