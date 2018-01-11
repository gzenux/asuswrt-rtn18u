AUTOMAKE_OPTIONS=foreign no-dependencies

CORELIBS = @CORELIBS@
MORELIBS = @MORELIBS@
MOREDEFS = @MOREDEFS@
INCLUDES = @INCS@
DEFS = @DEFS@ $(MOREDEFS)

CLEANFILES= config_grammar.c config_lexicon.c config_grammar.h

sbin_PROGRAMS = xsupplicant
xsupplicant_SOURCES = xsup_driver.c xsup_debug.c profile.c os_cardif.c \
			config.c eapol.c statemachine.c eap.c \
			key_statemachine.c eapol_key_type1.c interactive.c \
			eap_types/md5/eapmd5.c eap_types/tls/eaptls.c \
			eap_types/tls/tls_funcs.c eap_types/ttls/eapttls.c \
			eap_types/ttls/ttlsphase2.c eap_types/tls/tls_crypt.c \
			eap_types/mschapv2/mschapv2.c \
			eap_types/mschapv2/eapmschapv2.c \
			eap_types/peap/eappeap.c eap_types/peap/peap_phase2.c \
			eap_types/sim/eapsim.c eap_types/sim/fips.c \
			eap_types/sim/sha1.c eap_types/sim/simd5.c \
			eap_types/sim/simd11.c eap_types/sim/sm_handler.c \
			eap_types/leap/eapleap.c eap_types/leap/leapmd4.c \
			eap_types/otp/eapotp.c \
			xsup_ipc.c config_grammar.y  config_lexicon.l \
			ipc_callout.c cmd_handler.c

xsupplicant_LDADD = $(CORELIBS) $(MORELIBS)
