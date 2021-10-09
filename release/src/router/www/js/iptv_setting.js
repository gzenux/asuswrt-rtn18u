let model_stb_port = [
    { 'name': 'RT-AC87U', 'remove_switch_stb': [1, 5], 'rename_portname': null },
    { 'name': 'RT-AC5300R', 'remove_switch_stb': [1, 2, 5], 'rename_portname': { 'LAN3': 'LAN4', 'LAN4': 'LAN8' } },
    { 'name': 'RT-AC53', 'remove_switch_stb': [3, 4, 6], 'rename_portname': { 'LAN3': 'LAN1', 'LAN4': 'LAN2', 'LAN3 & LAN4': 'LAN1 & LAN2' } }
];

function generate_stb_x_options(modelid) {
    let default_options = [
        { 'name': 'none', 'value': '0' },
        { 'name': 'LAN1', 'value': '1' },
        { 'name': 'LAN2', 'value': '2' },
        { 'name': 'LAN3', 'value': '3' },
        { 'name': 'LAN4', 'value': '4' },
        { 'name': 'LAN1 & LAN2', 'value': '5' },
        { 'name': 'LAN3 & LAN4', 'value': '6' }
    ];
    let options = [];

    let model = null;
    for (let m in model_stb_port) {
        if (model_stb_port[m].name == modelid) {
            model = model_stb_port[m];
            break;
        }
    }

    if (model == null || model.remove_switch_stb == null) {
        options = default_options;
    } else {
        for (let i in model.remove_switch_stb)
            delete default_options[model.remove_switch_stb[i]];

        // Replace multiple LAN port strings with multiple other strings
        let RE = null;
        if (model.rename_portname != null)
            RE = new RegExp(Object.keys(model.rename_portname).join("|"), "gi");
        for (let i = 0; i < default_options.length; i++) {
            if (default_options[i] != null) {
                if (RE != null)
                    default_options[i].name = default_options[i].name.replace(RE, function (matched) { return model.rename_portname[matched]; });
                options.push(default_options[i]);
            }
        }
    }

    return options;
}

function generate_isp_profiles(modelid) {
    let profiles = [
        {
            'profile_name': 'none',
            'iptv_port': '',
            'voip_port': '',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'none',
            'switch_stb_x': '0',
            'switch_wan0tagid': '', 'switch_wan0prio': '0',
            'switch_wan1tagid': '', 'switch_wan1prio': '0',
            'switch_wan2tagid': '', 'switch_wan2prio': '0',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Unifi-Home',
            'iptv_port': 'LAN4',
            'voip_port': '',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'unifi_home',
            'switch_stb_x': '4',
            'switch_wan0tagid': '500', 'switch_wan0prio': '0',
            'switch_wan1tagid': '600', 'switch_wan1prio': '0',
            'switch_wan2tagid': '', 'switch_wan2prio': '0',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Unifi-Business',
            'iptv_port': '',
            'voip_port': '',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'unifi_biz',
            'switch_stb_x': '0',
            'switch_wan0tagid': '500', 'switch_wan0prio': '0',
            'switch_wan1tagid': '', 'switch_wan1prio': '0',
            'switch_wan2tagid': '', 'switch_wan2prio': '0',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Singtel-MIO',
            'iptv_port': 'LAN4',
            'voip_port': 'LAN3',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'singtel_mio',
            'switch_stb_x': '6',
            'switch_wan0tagid': '10', 'switch_wan0prio': '0',
            'switch_wan1tagid': '20', 'switch_wan1prio': '4',
            'switch_wan2tagid': '30', 'switch_wan2prio': '4',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Singtel-Others',
            'iptv_port': 'LAN4',
            'voip_port': '',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'singtel_others',
            'switch_stb_x': '4',
            'switch_wan0tagid': '10', 'switch_wan0prio': '0',
            'switch_wan1tagid': '20', 'switch_wan1prio': '4',
            'switch_wan2tagid': '', 'switch_wan2prio': '0',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'M1-Fiber',
            'iptv_port': '',
            'voip_port': 'LAN3',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'm1_fiber',
            'switch_stb_x': '3',
            'switch_wan0tagid': '1103', 'switch_wan0prio': '1',
            'switch_wan1tagid': '', 'switch_wan1prio': '0',
            'switch_wan2tagid': '1107', 'switch_wan2prio': '1',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Maxis-Fiber',
            'iptv_port': '',
            'voip_port': 'LAN3',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'maxis_fiber',
            'switch_stb_x': '3',
            'switch_wan0tagid': '621', 'switch_wan0prio': '0',
            'switch_wan1tagid': '', 'switch_wan1prio': '0',
            'switch_wan2tagid': '821,822', 'switch_wan2prio': '0',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Maxis-Fiber-Special',
            'iptv_port': '',
            'voip_port': 'LAN3',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'maxis_fiber_sp',
            'switch_stb_x': '3',
            'switch_wan0tagid': '11', 'switch_wan0prio': '0',
            'switch_wan1tagid': '', 'switch_wan1prio': '0',
            'switch_wan2tagid': '14', 'switch_wan2prio': '0',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Movistar Triple VLAN',
            'iptv_port': '',
            'voip_port': '',
            'bridge_port': '',
            'iptv_config': '1',
            'voip_config': '1',
            'switch_wantag': 'movistar',
            'switch_stb_x': '8',
            'switch_wan0tagid': '6', 'switch_wan0prio': '0',
            'switch_wan1tagid': '2', 'switch_wan1prio': '0',
            'switch_wan2tagid': '3', 'switch_wan2prio': '0',
            'mr_enable_x': '1',
            'emf_enable': '1',
            'wan_vpndhcp': '0',
            'quagga_enable': '1',
            'mr_altnet_x': '172.0.0.0/8',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Meo',
            'iptv_port': '',
            'voip_port': '',
            'bridge_port': 'LAN4',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'meo',
            'switch_stb_x': '4',
            'switch_wan0tagid': '12', 'switch_wan0prio': '0',
            'switch_wan1tagid': '12', 'switch_wan1prio': '0',
            'switch_wan2tagid': '', 'switch_wan2prio': '0',
            'mr_enable_x': '1',
            'emf_enable': '1',
            'wan_vpndhcp': '0',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '1'
        }, {
            'profile_name': 'Vodafone',
            'iptv_port': 'LAN3',
            'voip_port': '',
            'bridge_port': 'LAN4',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'vodafone',
            'switch_stb_x': '3',
            'switch_wan0tagid': '100', 'switch_wan0prio': '1',
            'switch_wan1tagid': '', 'switch_wan1prio': '0',
            'switch_wan2tagid': '105', 'switch_wan2prio': '1',
            'mr_enable_x': '1',
            'emf_enable': '1',
            'wan_vpndhcp': '0',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Hinet MOD',
            'iptv_port': 'LAN4',
            'voip_port': '',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'hinet',
            'switch_stb_x': '4',
            'switch_wan0tagid': '', 'switch_wan0prio': '0',
            'switch_wan1tagid': '', 'switch_wan1prio': '0',
            'switch_wan2tagid': '', 'switch_wan2prio': '0',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Stuff-Fibre',
            'iptv_port': '',
            'voip_port': '',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'stuff_fibre',
            'switch_stb_x': '0',
            'switch_wan0tagid': '10', 'switch_wan0prio': '0',
            'switch_wan1tagid': '', 'switch_wan1prio': '0',
            'switch_wan2tagid': '', 'switch_wan2prio': '0',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Maxis-Fiber-IPTV',
            'iptv_port': '',
            'voip_port': '',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'maxis_fiber_iptv',
            'switch_stb_x': '7',
            'switch_wan0tagid': '621', 'switch_wan0prio': '0',
            'switch_wan1tagid': '824', 'switch_wan1prio': '0',
            'switch_wan2tagid': '821,822', 'switch_wan2prio': '0',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'Maxis-Fiber-Special-IPTV',
            'iptv_port': '',
            'voip_port': '',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'maxis_fiber_sp_iptv',
            'switch_stb_x': '7',
            'switch_wan0tagid': '11', 'switch_wan0prio': '0',
            'switch_wan1tagid': '15', 'switch_wan1prio': '0',
            'switch_wan2tagid': '14', 'switch_wan2prio': '0',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }, {
            'profile_name': 'manual',
            'iptv_port': 'LAN4',
            'voip_port': 'LAN3',
            'bridge_port': '',
            'iptv_config': '0',
            'voip_config': '0',
            'switch_wantag': 'manual',
            'switch_stb_x': '0',
            'switch_wan0tagid': '', 'switch_wan0prio': '0',
            'switch_wan1tagid': '', 'switch_wan1prio': '0',
            'switch_wan2tagid': '', 'switch_wan2prio': '0',
            'mr_enable_x': '',
            'emf_enable': '',
            'wan_vpndhcp': '',
            'quagga_enable': '0',
            'mr_altnet_x': '',
            'ttl_inc_enable': '0'
        }
    ];

    let model = null;
    for (let m in model_stb_port) {
        if (model_stb_port[m].name == modelid) {
            model = model_stb_port[m];
            break;
        }
    }
    if (model != null && model.rename_portname != null) {
        // Replace multiple LAN port strings with multiple other strings
        let RE = new RegExp(Object.keys(model.rename_portname).join("|"), "gi");
        for (let i = 0; i < profiles.length; i++) {
            if (profiles[i].iptv_port != '')
                profiles[i].iptv_port = profiles[i].iptv_port.replace(RE, function (matched) { return model.rename_portname[matched]; });
            if (profiles[i].voip_port != '')
                profiles[i].voip_port = profiles[i].voip_port.replace(RE, function (matched) { return model.rename_portname[matched]; });
            if (profiles[i].bridge_port != '')
                profiles[i].bridge_port = profiles[i].bridge_port.replace(RE, function (matched) { return model.rename_portname[matched]; });
        }
    }

    return profiles;
}

function get_iptvSettings() {
    let based_modelid = '<% nvram_get("productid"); %>';
    return {
        'isp_profiles': generate_isp_profiles(based_modelid),
        'stb_x_options': generate_stb_x_options(based_modelid)
    };
}
