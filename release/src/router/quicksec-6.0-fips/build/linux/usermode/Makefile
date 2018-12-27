BUILDTYPE=$(shell if test -d ../../../src/lib/; then echo distro; else echo devel; fi)

ifeq ($(BUILDTYPE),devel)
QUICKSEC_SRCDIR ?= ../../../src
TOOLKIT_SRCDIR ?= ../../../../toolkit-trunk/src
TOOLKIT_TESTDIR ?= ../../../../toolkit-trunk/test
TOOLKIT_EXTERNALSRCDIR ?= ../../../../toolkit-trunk/external-src
else
QUICKSEC_SRCDIR ?= ../../../src
TOOLKIT_SRCDIR ?= ../../../src/lib
TOOLKIT_TESTDIR ?= ../../../test
TOOLKIT_EXTERNALSRCDIR ?= ../../../external-src
endif

override CFLAGS += -MMD -Wall -Wno-pointer-sign

override CPPFLAGS += \
    -I$(QUICKSEC_SRCDIR)/. \
    -I$(QUICKSEC_SRCDIR)/interceptor/include \
    -I$(QUICKSEC_SRCDIR)/interceptor/libkernelutil \
    -I$(QUICKSEC_SRCDIR)/ipsec \
    -I$(QUICKSEC_SRCDIR)/ipsec/hwaccel \
    -I$(TOOLKIT_SRCDIR)/sshdhcp \
    -I$(TOOLKIT_SRCDIR)/sshikev2 \
    -I$(TOOLKIT_SRCDIR)/sshisakmp \
    -I$(TOOLKIT_SRCDIR)/sshl2tp \
    -I$(TOOLKIT_SRCDIR)/sshppp \
    -I$(QUICKSEC_SRCDIR)/ipsec/quicksec \
    -I$(QUICKSEC_SRCDIR)/ipsec/quicksec/apps \
    -I$(QUICKSEC_SRCDIR)/ipsec/quicksec/engine \
    -I$(QUICKSEC_SRCDIR)/ipsec/quicksec/fastpath \
    -I$(QUICKSEC_SRCDIR)/ipsec/quicksec/fastpath/software \
    -I$(QUICKSEC_SRCDIR)/ipsec/quicksec/pme \
    -I$(QUICKSEC_SRCDIR)/ipsec/quicksec/policymanager \
    -I$(QUICKSEC_SRCDIR)/ipsec/util \
    -I$(TOOLKIT_SRCDIR)/sshapputil \
    -I$(TOOLKIT_SRCDIR)/sshasn1 \
    -I$(TOOLKIT_SRCDIR)/sshcert \
    -I$(TOOLKIT_SRCDIR)/sshcrypto \
    -I$(TOOLKIT_SRCDIR)/sshcipher \
    -I$(TOOLKIT_SRCDIR)/sshcryptocore \
    -I$(TOOLKIT_SRCDIR)/sshhash \
    -I$(TOOLKIT_SRCDIR)/sshmac \
    -I$(TOOLKIT_SRCDIR)/sshpk \
    -I$(TOOLKIT_SRCDIR)/sshrandom \
    -I$(TOOLKIT_SRCDIR)/sshcryptoaux \
    -I$(TOOLKIT_SRCDIR)/ssheap \
    -I$(TOOLKIT_SRCDIR)/sshenroll \
    -I$(TOOLKIT_SRCDIR)/sshexternalkey \
    -I$(TOOLKIT_SRCDIR)/sshhttp \
    -I$(TOOLKIT_SRCDIR)/sshldap \
    -I$(TOOLKIT_SRCDIR)/sshmath \
    -I$(TOOLKIT_SRCDIR)/sshpkcs \
    -I$(TOOLKIT_SRCDIR)/sshradius \
    -I$(TOOLKIT_SRCDIR)/sshsim \
    -I$(TOOLKIT_SRCDIR)/sshtls \
    -I$(TOOLKIT_SRCDIR)/sshutil \
    -I$(TOOLKIT_SRCDIR)/sshadt \
    -I$(TOOLKIT_SRCDIR)/sshaudit \
    -I$(TOOLKIT_SRCDIR)/sshcore \
    -I$(TOOLKIT_SRCDIR)/ssheloop \
    -I$(TOOLKIT_SRCDIR)/sshfsm \
    -I$(TOOLKIT_SRCDIR)/sshmisc \
    -I$(TOOLKIT_SRCDIR)/sshnet \
    -I$(TOOLKIT_SRCDIR)/sshpacketstream \
    -I$(TOOLKIT_SRCDIR)/sshstream \
    -I$(TOOLKIT_SRCDIR)/sshstrutil \
    -I$(TOOLKIT_SRCDIR)/sshsysutil \
    -I$(TOOLKIT_SRCDIR)/sshtestutil \
    -I$(TOOLKIT_SRCDIR)/sshvalidator \
    -I$(TOOLKIT_SRCDIR)/sshxml \
    -I$(TOOLKIT_EXTERNALSRCDIR)/zlib \
    -DSSH_BUILD_IPSEC

ifeq ($(DEBUG), 1)
override CPPFLAGS += -DDEBUG_LIGHT
else
override CFLAGS += \
    -Wno-unused-function \
    -Wno-unused-variable

# The compiler version detection works only for gcc and clang
COMPILER_MAJOR_VERSION := $(shell $(CC) -dumpversion |sed 's/\..*//')
COMPILER_MINOR_VERSION := $(shell $(CC) -dumpversion \
	|sed -r 's/[0-9]{1,}\.([0-9]{1,}).*/\1/')
NO_UNUSED_BUT_SET_VARIABLE_WARNING_SUPPORTED := $(shell \
	[ $(COMPILER_MAJOR_VERSION) -gt 3 -a $(COMPILER_MINOR_VERSION) -gt 5 ] \
	&& echo true)

ifeq ($(NO_UNUSED_BUT_SET_VARIABLE_WARNING_SUPPORTED),true)
override CFLAGS += -Wno-unused-but-set-variable
endif

endif

ifeq ($(SERVER), 1)
override CPPFLAGS += -DQUICKSEC_DIST_SERVER
endif

ifeq ($(CLIENT), 1)
override CPPFLAGS += -DQUICKSEC_DIST_CLIENT
endif

ifeq ($(VRF),MONTAVISTA)
override CPPFLAGS += -DHAVE_MVL_VRF
endif

ifeq ($(VRF),WINDRIVER)
override CPPFLAGS += -DHAVE_WRL_VRF -I$(KDIR)/include
endif

ifeq ($(CAPTURE),IP)
override CPPFLAGS += -DSSH_IPSEC_IP_ONLY_INTERCEPTOR
endif

ifeq ($(SMALL),1)
override CPPFLAGS += -DSSH_IPSEC_SMALL
endif

ifeq ($(AES),INTEL)
override CPPFLAGS += -DHAVE_AES -DHAVE_AES_INTEL_INSTRUCTION_SET
override CFLAGS += -maes -msse4.1 -mpclmul
endif

QUICKSEC_PROGRAMS := \
    quicksecpm \
    tinypm \
    clientpm \
    dtd-compress \
    make-vendor-id \
    ssh-berdump \
    ssh-certmake \
    ssh-certview \
    ssh-cmpclient \
    ssh-keytool \
    ssh-p12extract \
    ssh-p12make \
    ssh-scepclient \

-include Makefile.inc
-include Makefile.internal

ifeq ($(VRF),MONTAVISTA)
libbase.a: \
    sshlinuxnetconfig.o
endif

ifeq ($(VRF),WINDRIVER)
libbase.a: \
    sshlinuxnetconfig_wrl.o
endif

ifeq ($(VRF),)
libbase.a: \
    sshlinuxnetconfig.o
endif

ifeq ($(AES),INTEL)
libcrypto.a: \
    intel-aes.o
else
libcrypto.a: \
    rijndael.o
endif

all: $(QUICKSEC_PROGRAMS)

quicksecpm: \
    quicksec_dtd.o \
    quicksecpm.o \
    quicksecpm_audit.o \
    quicksecpm_xmlconf.o \
    quicksecpm_xmlconf_http.o \
    quicksecpm_unix.o \
    redirect_filter.o \
    libipsecpm.a \
    libproto.a \
    libcrypto.a \
    libbase.a

tinypm: \
    tinypm.o \
    libipsecpm.a \
    libproto.a \
    libcrypto.a \
    libbase.a

clientpm: \
    clientpm.o \
    libipsecpm.a \
    libproto.a \
    libcrypto.a \
    libbase.a

dtd-compress: \
    dtd-compress.o \
    libbase.a


make-vendor-id: \
    make-vendor-id.o \
    libcrypto.a \
    libbase.a

ssh-berdump: \
    ssh-berdump.o \
    dump-ber.o \
    iprintf.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-certmake: \
    ssh-certmake.o \
    dump-key.o \
    iprintf.o \
    parse-x509-forms.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-certview: \
    ssh-certview.o \
    dump-ber.o \
    dump-cert.o \
    dump-crl.o \
    dump-key.o \
    dump-other.o \
    iprintf.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-cmpclient: \
    ssh-cmpclient.o \
    au-ek.o \
    dump-ber.o \
    dump-cert.o \
    dump-key.o \
    ec-cmp.o \
    iprintf.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-keytool: \
    ssh-keytool.o \
    dump-key.o \
    iprintf.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-p12extract: \
    ssh-p12extract.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-p12make: \
    ssh-p12make.o \
    libproto.a \
    libcrypto.a \
    libbase.a

ssh-scepclient: \
    ssh-scepclient.o \
    au-ek.o \
    dump-ber.o \
    dump-cert.o \
    dump-key.o \
    ec-cep.o \
    iprintf.o \
    libproto.a \
    libcrypto.a \
    libbase.a

libipsecpm.a: \
    eng_pm_api_pm.o \
    eng_rules.o \
    eng_upcall.o \
    pad_auth_domain.o \
    pad_auth_passwd.o \
    pad_auth_radius.o \
    pad_authorization.o \
    pad_authorization_local.o \
    pad_ike.o \
    pad_ike_certs.o \
    pad_ike_certs_mscapi.o \
    pad_ike_eap.o \
    rac_virtual_ip.o \
    rac_virtual_ip_utils.o \
    rac_virtual_ip_cfgmode_st.o \
    rac_virtual_ip_l2tp_st.o \
    rac_virtual_ip_st.o \
    ras.o \
    ras_addrpool.o \
    ras_cfgmode_client_store.o \
    ras_dhcp_addrpool.o \
    ras_legacy_auth_server.o \
    ras_radius_acct.o \
    sad_ike.o \
    sad_ike_common_st.o \
    sad_ike_i_negotiation_st.o \
    sad_ike_initiator_st.o \
    sad_ike_spis.o \
    sad_mobike.o \
    sad_mobike_st.o \
    sad_sa_handler.o \
    sad_sa_handler_manual.o \
    sad_sa_handler_st.o \
    spd_batch_st.o \
    spd_config_st.o \
    spd_iface_st.o \
    spd_ike.o \
    spd_ike_blacklist.o \
    spd_ike_delete.o \
    spd_ike_init.o \
    spd_ike_psk.o \
    spd_main.o \
    spd_main_engine.o \
    spd_main_st.o \
    spd_rule_lookup.o \
    spd_rules.o \
    spd_services.o \
    spd_shutdown_st.o \
    spd_tunnels.o \
    spd_tunnels_ike.o \
    util.o \
    util_algorithms.o \
    util_alloc.o \
    util_audit.o \
    util_cm.o \
    util_cm_access.o \
    util_cm_notify.o \
    util_compat.o \
    util_connection.o \
    util_dnsresolver.o \
    util_dpd.o \
    util_ek.o \
    util_engine.o \
    util_ek_st.o \
    util_ike_certs.o \
    util_ike_cfgmode.o \
    util_ike_confutils.o \
    util_ike_id.o \
    util_ike_ipsec.o \
    util_ike_sautils.o \
    util_ike_spis.o \
    util_ike_tsutils.o \
    util_ipsec.o \
    util_l2tp.o \
    util_l2tp_lns_st.o \
    util_linearize.o \
    util_mscapi.o \
    util_nameserver.o \
    util_peer.o \
    util_render.o \
    util_servers.o \
    util_statistics.o \
    util_tables.o \
    util_tcpencap.o \
    util_unknown_spis.o \
    util_virtual_adapter.o \
    engine_pm_api_util.o \
    ip_interfaces.o \
    virtual_adapter_util.o

libproto.a: \
    ssh_berfile.o \
    sshasn1.o \
    sshasn1create.o \
    sshasn1print.o \
    sshber-util.o \
    sshber.o \
    pem-format.o \
    ssh1encode.o \
    ssh2pubkeyencode.o \
    sshcipherlist.o \
    sshkeyblob1.o \
    sshkeyblob2.o \
    sshprvkey.o \
    sshpsystem.o \
    sshpubkey.o \
    sshsnlist.o \
    crmf-crypto.o \
    enroll-pkix.o \
    enroll-scep.o \
    enroll.o \
    scep-client.o \
    scep-common.o \
    x509cmp.o \
    x509cmp_decode.o \
    x509cmp_encode.o \
    x509cmp_util.o \
    cert-db.o \
    cmi-cert.o \
    cmi-config.o \
    cmi-crl.o \
    cmi-debug.o \
    cmi-edb.o \
    cmi-http.o \
    cmi-key-pk.o \
    cmi-key.o \
    cmi-ldap.o \
    cmi-list.o \
    cmi-map.o \
    cmi-ocsp.o \
    cmi-pcnst.o \
    cmi-pkcs7.o \
    cmi-trust.o \
    cmi.o \
    ssheap_aka.o \
    ssheap_common.o \
    ssheap_config.o \
    ssheap_connection.o \
    ssheap_md5.o \
    ssheap_mschap.o \
    ssheap_otp.o \
    ssheap_packet.o \
    ssheap_params.o \
    ssheap_pass_through.o \
    ssheap_protocol.o \
    ssheap_radius.o \
    ssheap_setup.o \
    ssheap_sim.o \
    ssheap_tls.o \
    ssheap_tokencard.o \
    dummyacc.o \
    dummyprov.o \
    extkeyprov.o \
    genaccdevice.o \
    genaccprovider.o \
    softacc.o \
    softprovider.o \
    sshek_providers_toolkit.o \
    sshexternalkey.o \
    sshsoftkey.o \
    sshhttpclient.o \
    sshhttpserver.o \
    sshhttputils.o \
    dhcp.o \
    dhcp_options.o \
    dhcp_packet.o \
    dhcp_states.o \
    dhcp_util.o \
    dhcpv6_options.o \
    dhcpv6_packet.o \
    dhcpv6_states.o \
    dhcpv6_util.o \
    ikev2-auth-init-in.o \
    ikev2-auth-init-out.o \
    ikev2-auth-resp-in.o \
    ikev2-auth-resp-out.o \
    ikev2-auth2-init-in.o \
    ikev2-auth2-init-out.o \
    ikev2-auth2-resp-in.o \
    ikev2-auth2-resp-out.o \
    ikev2-child-init-in.o \
    ikev2-child-init-out.o \
    ikev2-child-resp-in.o \
    ikev2-child-resp-out.o \
    ikev2-common-info.o \
    ikev2-confutil.o \
    ikev2-crypto.o \
    ikev2-debug.o \
    ikev2-decode.o \
    ikev2-eap-auth.o \
    ikev2-encode.o \
    ikev2-fb-cfgmode-conv.o \
    ikev2-fb-cfgmode.o \
    ikev2-fb-conv.o \
    ikev2-fb-id-conv.o \
    ikev2-fb-init-info.o \
    ikev2-fb-init-p1.o \
    ikev2-fb-init-qm.o \
    ikev2-fb-init.o \
    ikev2-fb-nat-t.o \
    ikev2-fb-policy-certs.o \
    ikev2-fb-policy-p1.o \
    ikev2-fb-policy-p2.o \
    ikev2-fb-policy-qm.o \
    ikev2-fb-sa-conv.o \
    ikev2-fb-ts-conv.o \
    ikev2-fb-util.o \
    ikev2-fb-xauth.o \
    ikev2-groups.o \
    ikev2-ike-rekey-init-in.o \
    ikev2-ike-rekey-init-out.o \
    ikev2-ike-rekey-resp-in.o \
    ikev2-ike-rekey-resp-out.o \
    ikev2-info-init-in.o \
    ikev2-info-init-out.o \
    ikev2-info-resp-in.o \
    ikev2-info-resp-out.o \
    ikev2-init-ike-sa.o \
    ikev2-init-info-sa.o \
    ikev2-init-ipsec-sa.o \
    ikev2-init.o \
    ikev2-ke-error-out.o \
    ikev2-linearize.o \
    ikev2-mobike.o \
    ikev2-multiple-auth.o \
    ikev2-nat-t.o \
    ikev2-packet-debug.o \
    ikev2-packet-decode.o \
    ikev2-packet-encode.o \
    ikev2-pk-auth.o \
    ikev2-prfplus.o \
    ikev2-recv.o \
    ikev2-redirect.o \
    ikev2-rekey-ike.o \
    ikev2-render-ike-spi.o \
    ikev2-render-payload.o \
    ikev2-request-cookie-out.o \
    ikev2-sa-init-error.o \
    ikev2-sa-init-init-in.o \
    ikev2-sa-init-init-out.o \
    ikev2-sa-init-resp-in.o \
    ikev2-sa-init-resp-out.o \
    ikev2-sautil.o \
    ikev2-send.o \
    ikev2-shared-key-auth.o \
    ikev2-state-common.o \
    ikev2-state.o \
    ikev2-string-attribute-type.o \
    ikev2-string-auth-method.o \
    ikev2-string-cert-encoding.o \
    ikev2-string-id.o \
    ikev2-string-notify.o \
    ikev2-string-payload.o \
    ikev2-string-protocol.o \
    ikev2-string-transform.o \
    ikev2-tables.o \
    ikev2-tsutil.o \
    ikev2-window.o \
    isakmp.o \
    isakmp_attrs.o \
    isakmp_cookie.o \
    isakmp_crypt.o \
    isakmp_da.o \
    isakmp_debug.o \
    isakmp_finalize.o \
    isakmp_groups.o \
    isakmp_id.o \
    isakmp_init.o \
    isakmp_input.o \
    isakmp_linearize.o \
    isakmp_misc.o \
    isakmp_output.o \
    isakmp_packet.o \
    isakmp_packet_debug.o \
    isakmp_reply.o \
    isakmp_sa.o \
    isakmp_stat.o \
    isakmp_state.o \
    isakmp_string_payload.o \
    isakmp_tables.o \
    isakmp_udp.o \
    isakmp_util.o \
    sshl2tp.o \
    sshl2tp_message.o \
    sshl2tp_st_cc_initiator.o \
    sshl2tp_st_cc_responder.o \
    sshl2tp_st_lac_ic.o \
    sshl2tp_st_lac_oc.o \
    sshl2tp_st_lns_ic.o \
    sshl2tp_st_lns_oc.o \
    sshl2tp_st_session.o \
    sshl2tp_st_tunnel.o \
    sshl2tp_tables.o \
    sshl2tp_transport.o \
    sshl2tp_util.o \
    ldap-bind.o \
    ldap-connect.o \
    ldap-conv.o \
    ldap-ext.o \
    ldap-filtertostr.o \
    ldap-init.o \
    ldap-input.o \
    ldap-modify.o \
    ldap-object.o \
    ldap-output.o \
    ldap-search.o \
    ldap-strtofilter.o \
    pkcs1-formats.o \
    pkcs12-conv.o \
    pkcs12.o \
    pkcs5.o \
    pkcs6-cert.o \
    pkcs6.o \
    pkcs7-common.o \
    pkcs7-create-sync.o \
    pkcs7-create.o \
    pkcs7-decode.o \
    pkcs7-encode.o \
    pkcs7-receive-sync.o \
    pkcs7-receive.o \
    pkcs8.o \
    sshppp_auth.o \
    sshppp_chap.o \
    sshppp_chap_fsm.o \
    sshppp_config.o \
    sshppp_eap_fsm.o \
    sshppp_events.o \
    sshppp_fcs.o \
    sshppp_flush.o \
    sshppp_fsm.o \
    sshppp_io_stream.o \
    sshppp_ipcp.o \
    sshppp_ipcp_config.o \
    sshppp_lcp.o \
    sshppp_lcp_config.o \
    sshppp_linkpkt.o \
    sshppp_pap_fsm.o \
    sshppp_protocol.o \
    sshppp_protocol_fsm.o \
    sshppp_radius.o \
    sshppp_setup.o \
    sshppp_thread.o \
    sshppp_timer.o \
    sshradius.o \
    sshradius_tables.o \
    sshradius_url.o \
    sshsim_sample.o \
    tls_accel.o \
    tls_alert.o \
    tls_appstream.o \
    tls_async.o \
    tls_cache.o \
    tls_crypto.o \
    tls_downstream.o \
    tls_extra.o \
    tls_kex.o \
    tls_kextrans.o \
    tls_kt_RCertificate.o \
    tls_kt_RCertificateRequest.o \
    tls_kt_RCertificateVerify.o \
    tls_kt_RChangeCipher.o \
    tls_kt_RClientHello.o \
    tls_kt_RClientKeyExchange.o \
    tls_kt_RFinished.o \
    tls_kt_RServerHello.o \
    tls_kt_RServerHelloDone.o \
    tls_kt_RServerKeyExchance.o \
    tls_kt_WCertificate.o \
    tls_kt_WCertificateRequest.o \
    tls_kt_WCertificateVerify.o \
    tls_kt_WChangeCipher.o \
    tls_kt_WClientHello.o \
    tls_kt_WClientKeyExchance.o \
    tls_kt_WFinished.o \
    tls_kt_WHelloRequest.o \
    tls_kt_WServerHello.o \
    tls_kt_WServerHelloDone.o \
    tls_kt_WServerKeyExchance.o \
    tls_kt_cont_funcs.o \
    tls_main.o \
    tls_multihash.o \
    tls_record.o \
    tls_suites.o \
    tls_tempkey.o \
    tls_util.o \
    dn-der.o \
    dn-ldap.o \
    dn-util.o \
    eckeys.o \
    ocsp_client.o \
    ocsp_common.o \
    ocsp_http.o \
    oid.o \
    sshglist.o \
    sshpswbmac.o \
    x509.o \
    x509cert.o \
    x509cert_decode.o \
    x509cert_encode.o \
    x509cert_sync.o \
    x509crl.o \
    x509crl_decode.o \
    x509crl_encode.o \
    x509crl_sync.o \
    x509crmf_decode.o \
    x509crmf_encode.o \
    x509crmf_value.o \
    x509ext_decode.o \
    x509ext_encode.o \
    x509get.o \
    x509init.o \
    x509name_decode.o \
    x509name_encode.o \
    x509private.o \
    x509public_decode.o \
    x509public_encode.o \
    x509req_decode.o \
    x509req_encode.o \
    x509set.o \
    x509signature.o \
    sshxml_accessors.o \
    sshxml_chain.o \
    sshxml_dom.o \
    sshxml_input_data.o \
    sshxml_input_file.o \
    sshxml_parser.o \
    sshxml_tables.o \
    sshxml_verifier.o \
    sshxml_verifier_dfa.o

libcrypto.a: \
    des.o \
    mode-ccm.o \
    mode-gcm.o \
    mscapi-cipher.o \
    nociph.o \
    octeon-cipher.o \
    crypto_init.o \
    crypto_tests.o \
    genaux.o \
    namelist.o \
    hash-oid.o \
    md5.o \
    mscapi-hash.o \
    octeon-hash.o \
    sha.o \
    sha256.o \
    sha512.o \
    hmac.o \
    macs.o \
    xcbc-mac.o \
    dl-dh.o \
    dl-dsa.o \
    dl-generate.o \
    dl-stack.o \
    dl-utility.o \
    dlfix.o \
    dsa-maker.o \
    dsa-user.o \
    ecp-maker.o \
    ecp-user.o \
    ecpfix.o \
    ecpglue.o \
    genciph.o \
    genhash.o \
    genmac.o \
    genmp-integer.o \
    genmp-prime.o \
    genpkcs.o \
    genpkcs_dh.o \
    genpkcs_private.o \
    genpkcs_public.o \
    libmonitor.o \
    nist-sp-800-90.o \
    nist-health-test.o \
    pkcs1.o \
    rsa-generate.o \
    rsa-maker.o \
    rsa-operation.o \
    rsa-user.o \
    rsa-utility.o \
    sshcryptoaux.o \
    ssh-pk-export.o \
    ssh-pk-group.o \
    ssh-pk-prv-def.o \
    ssh-pk-prv-gen.o \
    sshproxykey.o \
    sshrgf-mgf1.o \
    sshrgf-oaep.o \
    sshrgf-pss.o \
    sshrgf.o \
    genrand.o \
    ansi_x962.o \
    md4.o \
    singledes.o \
    randompool.o \
    aes_keywrap.o \
    bufhash.o \
    bufzip.o \
    genauxmp.o \
    keyexpand.o \
    oldimportapi.o \
    pkcs1_pad.o \
    sshcipheralias.o \
    sshrandompoll.o \
    sshmp-2adic.o \
    sshmp-arithmetic-extra.o \
    sshmp-arithmetic.o \
    sshmp-convabs.o \
    sshmp-ecp.o \
    sshmp-init.o \
    sshmp-integer-core.o \
    sshmp-integer-misc.o \
    sshmp-intmod.o \
    sshmp-montgomery.o \
    sshmp-naf.o \
    sshmp-powm.o \
    sshmp-tests.o \
    sshmp-xuint.o \
    sshsieve.o \
    sshmp-kernel.o \
    adler32.o \
    compress.o \
    crc32.o \
    deflate.o \
    gzio.o \
    infblock.o \
    infcodes.o \
    inffast.o \
    inflate.o \
    inftrees.o \
    infutil.o \
    trees.o \
    uncompr.o \
    zutil.o

libbase.a: \
    sshadt.o \
    sshadt_array.o \
    sshadt_assoc.o \
    sshadt_avltree.o \
    sshadt_conv.o \
    sshadt_list.o \
    sshadt_map.o \
    sshadt_priority_heap.o \
    sshadt_ranges.o \
    sshaudit.o \
    sshaudit_file.o \
    sshaudit_syslog.o \
    sshaudit_tables.o \
    sshaudit_util.o \
    sshbprintf.o \
    sshbuffer.o \
    sshcalendar.o \
    sshdebug.o \
    sshdllist.o \
    sshdlqueue.o \
    sshenum.o \
    sshenumcase.o \
    sshentropy.o \
    sshfastalloc.o \
    sshfatal.o \
    sshgetopt.o \
    sshglobals.o \
    sshmalloc.o \
    sshmatch.o \
    sshmemcmp.o \
    sshobstack.o \
    sshrand.o \
    sshrecalloc.o \
    sshsimplehashtable.o \
    sshsnprintf.o \
    sshtime.o \
    sshtimemeasure.o \
    sshustr.o \
    sshutil.o \
    sshxbuffer.o \
    sshxmalloc.o \
    sshoperation.o \
    sshthreadpool.o \
    sshtimeouts.o \
    sshfsm.o \
    sshnothreads.o \
    sshthreadedtimeout.o \
    sshunixeloop.o \
    sshbufaux.o \
    sshcrc32.o \
    sshdecay.o \
    sshgenutils.o \
    sshdnserror.o \
    sshdnsnameserver.o \
    sshdnspacket.o \
    sshdnspacketrender.o \
    sshdnsquery.o \
    sshdnsrender.o \
    sshdnsresolver.o \
    sshdnsrrdataprint.o \
    sshdnsrrsetcache.o \
    sshdnsrrsetrender.o \
    sshdnsrrtype.o \
    sshdnstransport.o \
    sshdnstransporttcp.o \
    sshdnstransportudp.o \
    sshicmp-util.o \
    sshinet.o \
    sshinetbits.o \
    sshinetcalc.o \
    sshinetcompare.o \
    sshinetencode.o \
    sshinetether.o \
    sshinethash.o \
    sshinetmapped.o \
    sshinetmask.o \
    sshinetmerge.o \
    sshinetnetmask.o \
    sshinetparse.o \
    sshinetprint.o \
    sshinetproto.o \
    sshinetrender.o \
    sshinetscope.o \
    sshinetstrtobin.o \
    sshnameserver.o \
    sshnetconfig.o \
    sshpdbg.o \
    sshsocks.o \
    sshtcp.o \
    sshudp-ip.o \
    sshudp-str.o \
    sshurl.o \
    sshunixlocalstream.o \
    sshunixtcp.o \
    sshunixtcplocalstream.o \
    sshunixudp.o \
    sshvrf.o \
    sshlinuxnetevent.o \
    sshlinuxnetmac.o \
    sshpacketimpl.o \
    sshpacketstream.o \
    sshpacketwrapper.o \
    sshdatastream.o \
    sshfilterstream.o \
    sshstream.o \
    sshstreamconnect.o \
    sshstreampair.o \
    sshbase16.o \
    sshbase64.o \
    sshbitvector.o \
    sshencode.o \
    sshencodetypes.o \
    sshfingerprint.o \
    sshmiscstring.o \
    sshregex.o \
    sshstr.o \
    sshutf8.o \
    sshfilebuffer.o \
    sshfileio.o \
    sshmallocspare.o \
    sshsignals.o \
    sshthreadedmbox.o \
    sshunixdevicestream.o \
    sshunixdirectory.o \
    sshunixfdstream.o

$(QUICKSEC_PROGRAMS):
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

%.a:
	$(AR) rcs $@ $^

depend:
	cat *.d >Makefile.depend

nodepend:
	rm -f Makefile.depend

clean:
	rm -f *.o *.d *.a $(QUICKSEC_PROGRAMS) Makefile.depend

vpath %.c \
    $(TOOLKIT_SRCDIR)/certutils \
    $(TOOLKIT_SRCDIR)/sshdhcp \
    $(TOOLKIT_SRCDIR)/sshikev2 \
    $(TOOLKIT_SRCDIR)/sshisakmp \
    $(TOOLKIT_SRCDIR)/sshl2tp \
    $(TOOLKIT_SRCDIR)/sshppp \
    $(QUICKSEC_SRCDIR)/ipsec/quicksec \
    $(QUICKSEC_SRCDIR)/ipsec/quicksec/apps \
    $(QUICKSEC_SRCDIR)/ipsec/quicksec/engine \
    $(QUICKSEC_SRCDIR)/ipsec/quicksec/pme \
    $(QUICKSEC_SRCDIR)/ipsec/quicksec/policymanager \
    $(QUICKSEC_SRCDIR)/ipsec/util \
    $(TOOLKIT_SRCDIR)/sshapputil \
    $(TOOLKIT_SRCDIR)/sshasn1 \
    $(TOOLKIT_SRCDIR)/sshcert \
    $(TOOLKIT_SRCDIR)/sshcipher \
    $(TOOLKIT_SRCDIR)/sshcryptocore \
    $(TOOLKIT_SRCDIR)/sshhash \
    $(TOOLKIT_SRCDIR)/sshmac \
    $(TOOLKIT_SRCDIR)/sshpk \
    $(TOOLKIT_SRCDIR)/sshrandom \
    $(TOOLKIT_SRCDIR)/sshcryptoaux \
    $(TOOLKIT_SRCDIR)/ssheap \
    $(TOOLKIT_SRCDIR)/sshenroll \
    $(TOOLKIT_SRCDIR)/sshexternalkey \
    $(TOOLKIT_SRCDIR)/sshhttp \
    $(TOOLKIT_SRCDIR)/sshldap \
    $(TOOLKIT_SRCDIR)/sshmath \
    $(TOOLKIT_SRCDIR)/sshpkcs \
    $(TOOLKIT_SRCDIR)/sshradius \
    $(TOOLKIT_SRCDIR)/sshsim \
    $(TOOLKIT_SRCDIR)/sshtls \
    $(TOOLKIT_SRCDIR)/sshadt \
    $(TOOLKIT_SRCDIR)/sshaudit \
    $(TOOLKIT_SRCDIR)/sshcore \
    $(TOOLKIT_SRCDIR)/ssheloop \
    $(TOOLKIT_SRCDIR)/sshfsm \
    $(TOOLKIT_SRCDIR)/sshmisc \
    $(TOOLKIT_SRCDIR)/sshnet \
    $(TOOLKIT_SRCDIR)/sshpacketstream \
    $(TOOLKIT_SRCDIR)/sshstream \
    $(TOOLKIT_SRCDIR)/sshstrutil \
    $(TOOLKIT_SRCDIR)/sshsysutil \
    $(TOOLKIT_SRCDIR)/sshvalidator \
    $(TOOLKIT_SRCDIR)/sshxml \
    $(TOOLKIT_EXTERNALSRCDIR)/zlib

-include Makefile.depend
