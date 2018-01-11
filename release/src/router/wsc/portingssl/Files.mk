#####################################################################
#
#/* --------------------------------------------------------------------
# *
# * Copyright 2002 by Realtek Semiconductor Corp.
# *
# * --------------------------------------------------------------------*/
#
#
#####################################################################

USER_OBJ   = $(OUTDIR)/mem.o $(OUTDIR)/mem_clr.o $(OUTDIR)/bn_add.o $(OUTDIR)/bn_asm.o $(OUTDIR)/bn_const.o $(OUTDIR)/bn_ctx.o \
		$(OUTDIR)/bn_div.o $(OUTDIR)/bn_exp.o $(OUTDIR)/bn_gcd.o $(OUTDIR)/bn_lib.o $(OUTDIR)/bn_mod.o $(OUTDIR)/bn_mont.o \
		$(OUTDIR)/bn_mul.o $(OUTDIR)/bn_prime.o $(OUTDIR)/bn_rand.o $(OUTDIR)/bn_recp.o $(OUTDIR)/bn_shift.o $(OUTDIR)/bn_sqr.o \
		$(OUTDIR)/bn_word.o $(OUTDIR)/dh_check.o $(OUTDIR)/dh_gen.o $(OUTDIR)/dh_key.o $(OUTDIR)/dh_lib.o $(OUTDIR)/digest.o \
		$(OUTDIR)/m_sha1.o $(OUTDIR)/hmac.o $(OUTDIR)/md_rand.o $(OUTDIR)/rand_lib.o $(OUTDIR)/sha1dgst.o $(OUTDIR)/sha256.o \
		$(OUTDIR)/aes_cbc.o $(OUTDIR)/fips_aes_core.o


ifeq ($(test), 1)
# AES_TEST: dump AES operation and do NIST vector test
# AES_DECRYPT: add decryption code, it's no need in 4-way handshaking
# SEC_DEBUG: dump security operation and do MBOA 0.9 vector test of 4-way handshaking
# OPTIMIZE_SIZE: code size issue, remove table lookup method
CFLAGS += -DAES_TEST -DAES_DECRYPT -DSEC_DEBUG -DOPTIMIZE_SIZE
else
ifeq ($(test), 2)
CFLAGS += -DOPTIMIZE_SIZE -DSEC_DEBUG -DSOFT_ENCRYPTION
else
CFLAGS += -DOPTIMIZE_SIZE
endif
endif			

OBJFILES   = $(USER_OBJ)

######################./Crypto/#####################################

$(OUTDIR)/mem.o: ./crypto/mem.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/mem.o ./crypto/mem.c	

$(OUTDIR)/mem_clr.o: ./crypto/mem_clr.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/mem_clr.o ./crypto/mem_clr.c	
		
######################./Crypto/bn/#####################################

$(OUTDIR)/bn_add.o: ./crypto/bn/bn_add.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_add.o ./crypto/bn/bn_add.c

$(OUTDIR)/bn_asm.o: ./crypto/bn/bn_asm.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_asm.o ./crypto/bn/bn_asm.c

$(OUTDIR)/bn_const.o: ./crypto/bn/bn_const.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_const.o ./crypto/bn/bn_const.c
		
$(OUTDIR)/bn_ctx.o: ./crypto/bn/bn_ctx.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_ctx.o ./crypto/bn/bn_ctx.c

$(OUTDIR)/bn_div.o: ./crypto/bn/bn_div.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_div.o ./crypto/bn/bn_div.c			
	
$(OUTDIR)/bn_exp.o: ./crypto/bn/bn_exp.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_exp.o ./crypto/bn/bn_exp.c
	
$(OUTDIR)/bn_gcd.o: ./crypto/bn/bn_gcd.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_gcd.o ./crypto/bn/bn_gcd.c

$(OUTDIR)/bn_lib.o: ./crypto/bn/bn_lib.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_lib.o ./crypto/bn/bn_lib.c
	
$(OUTDIR)/bn_mod.o: ./crypto/bn/bn_mod.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_mod.o ./crypto/bn/bn_mod.c
	
$(OUTDIR)/bn_mont.o: ./crypto/bn/bn_mont.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_mont.o ./crypto/bn/bn_mont.c
	
$(OUTDIR)/bn_mul.o: ./crypto/bn/bn_mul.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_mul.o ./crypto/bn/bn_mul.c
	
$(OUTDIR)/bn_prime.o: ./crypto/bn/bn_prime.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_prime.o ./crypto/bn/bn_prime.c
	
$(OUTDIR)/bn_rand.o: ./crypto/bn/bn_rand.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_rand.o ./crypto/bn/bn_rand.c
	
$(OUTDIR)/bn_recp.o: ./crypto/bn/bn_recp.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_recp.o ./crypto/bn/bn_recp.c	

$(OUTDIR)/bn_shift.o: ./crypto/bn/bn_shift.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_shift.o ./crypto/bn/bn_shift.c	

$(OUTDIR)/bn_sqr.o: ./crypto/bn/bn_sqr.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_sqr.o ./crypto/bn/bn_sqr.c	

$(OUTDIR)/bn_word.o: ./crypto/bn/bn_word.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/bn_word.o ./crypto/bn/bn_word.c	
	
######################./Crypto/dh/#####################################

$(OUTDIR)/dh_check.o: ./crypto/dh/dh_check.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/dh_check.o ./crypto/dh/dh_check.c	

$(OUTDIR)/dh_gen.o: ./crypto/dh/dh_gen.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/dh_gen.o ./crypto/dh/dh_gen.c	

$(OUTDIR)/dh_key.o: ./crypto/dh/dh_key.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/dh_key.o ./crypto/dh/dh_key.c	

$(OUTDIR)/dh_lib.o: ./crypto/dh/dh_lib.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/dh_lib.o ./crypto/dh/dh_lib.c	

######################./Crypto/evp/#####################################

$(OUTDIR)/digest.o: ./crypto/evp/digest.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/digest.o ./crypto/evp/digest.c	

$(OUTDIR)/m_sha1.o: ./crypto/evp/m_sha1.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/m_sha1.o ./crypto/evp/m_sha1.c	

######################./Crypto/hmac/#####################################

$(OUTDIR)/hmac.o: ./crypto/hmac/hmac.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/hmac.o ./crypto/hmac/hmac.c	

######################./Crypto/hmac/#####################################

$(OUTDIR)/md_rand.o: ./crypto/rand/md_rand.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/md_rand.o ./crypto/rand/md_rand.c	
	
$(OUTDIR)/rand_lib.o: ./crypto/rand/rand_lib.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/rand_lib.o ./crypto/rand/rand_lib.c	
	
######################./Crypto/sha/#####################################

$(OUTDIR)/sha1dgst.o: ./crypto/sha/sha1dgst.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/sha1dgst.o ./crypto/sha/sha1dgst.c	

$(OUTDIR)/sha256.o: ./crypto/sha/sha256.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/sha256.o ./crypto/sha/sha256.c	

######################./Crypto/aes/#####################################
$(OUTDIR)/fips_aes_core.o: ./crypto/aes/fips_aes_core.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/fips_aes_core.o ./crypto/aes/fips_aes_core.c

$(OUTDIR)/aes_cbc.o: ./crypto/aes/aes_cbc.c 
	$(CC) -c $(CFLAGS) -o $(OUTDIR)/aes_cbc.o ./crypto/aes/aes_cbc.c
										
#####################################################################




clean :
	$(RM) -f $(OUTDIR)/*.o
	$(RM) -f $(OUTLIBDIR)/*.a