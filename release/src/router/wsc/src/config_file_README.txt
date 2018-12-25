wlan_fifo0 ="/var/wscd-wlan0.fifo"
wlan_fifo1 ="/var/wscd-wlan1.fifo"
#if "use_ie"!=2 and "disable_auto_gen_ssid" != 1 then use this parameter as prefix of SSID
#default case use "WPS"  as prefix of SSID
SSID_prefix = "Reaktek_AP_"

# 1=use ie ; 0 = not use ; 2= used ie & auto generated SSID 
# in the format of ssid+last 2 bytes mac
use_ie = 1

# AUTH_OPEN=1, AUTH_WPAPSK=2, AUTH_SHARED=4, AUTH_WPA=8, AUTH_WPA2=0x10, AUTH_WPA2PSK=0x20
auth_type_flags = 39

# ENCRYPT_NONE=1, ENCRYPT_WEP=2, ENCRYPT_TKIP=4, ENCRYPT_AES=8
encrypt_type_flags = 15

uuid = 63041253101920061228aabbccddeeff
device_name = "RTKAP-123"
manufacturer = "Realtek Semiconductor Corp."
manufacturerURL = "http://www.realtek.com/"
modelURL = "http://www.realtek.com/"
model_name = "RTL8xxx"
model_num = "EV-2010-09-20"
serial_num = "123456789012347"
modelDescription = "WLAN Access Point"
device_attrib_id = 1
device_oui = 0050f204
device_category_id = 6
device_sub_category_id = 1

# PASS_ID_DEFAULT=0, PASS_ID_USER=1, PASS_ID_MACHINE=2, PASS_ID_REKEY=3,
# PASS_ID_PB=4, PASS_ID_REG=5, PASS_ID_RESERVED=6
device_password_id = 0

tx_timeout = 5
resent_limit = 2
reg_timeout = 120
block_timeout = 60
# Those parameters are supported by WPS daemon starting from V1.2.
# Need to patch /rtl8186/linux-2.4.18/drivers/char/rtl_gpio.c if
# you want to use wireless LED instead of WPS LED.
WPS_START_LED_GPIO_number = 2
WPS_END_LED_unconfig_GPIO_number = 0
WPS_END_LED_config_GPIO_number = 0
WPS_PBC_overlapping_GPIO_number = 1
PBC_overlapping_LED_time_out = 30

# When 0, WPS daemon will issue command 'flash set wlan0 value' to update setting
# When 1, WPS daemon will issue command 'flash set value' to update setting
# When 2, WPS daemon will update setting to a file '/tmp/flash_param'
No_ifname_for_flash_set = 0

# Disable to send dis-association to STA after WPS is done. 1:disable, 0:enable
#disable_disconnect = 1

# Disable auto generate SSID in un-configured state
#disable_auto_gen_ssid = 1


#(A)Manual assigned encryption type. 0:disable, 1:WPA-TKIP, 2:WPA2-AES, 3:Mixed-AES-TKIP
#manual_key_type = 2

#(A1)if manual_key_type == 1~3 ,
# you can alternative select 1)assigned manual psk value(manual_key) 
# or 2)assigned random key length(random_key_len)
# PSK valid key length between 8~64 ; if manual_key no assigned  and random_key_len no assigned
# then use 1234567890 as default
#manual_key = 1234567890
#random_key_len = 64

#(A2)if manual_key_type == 0,you can assigned PSK length between 8~64
#PSK_LEN = 64

# Disable hidden AP when wsc is activiated
disable_hidden_ap = 1

#if "use_ie"!=2 and "disable_auto_gen_ssid" != 1 then use this parameter as prefix of SSID
#default case use "WPS"  as prefix of SSID
#SSID_prefix = "RTKAP_"

button_hold_time = 3

# Enable the fix for Windows-Zero-Config WEP issue
fix_wzc_wep = 0

#for 92D concurrent mode, there are two wlan interfaces, we can use this parameter to select one interface to do WPS
#if botton_hold_time_for_wlan0 <= 5, do trigger to wlan0, if botton_hold_time_for_wlan0 >5, do trigger to wlan1.
#if wlan0 and wlan1 are both on AP mode, we don't care this parameter.
button_hold_time_for_first_if = 5
