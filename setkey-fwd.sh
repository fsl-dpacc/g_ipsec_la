#!/usr/sbin/setkey -f
#
#
# Example ESP Tunnel for VPN.
#  left NW (ixia)    gateway A (LS 2085 guest)         Gateway-B (10.78.87.40)    right NW (ixia)
#     port 2.9        eth0          eth1                eth5            eth2        port 2.10
#    1.1.1.0/24 -- [1.1.1.203   192.168.3.211] ==== [192.168.3.212   2.2.2.203] -- 2.2.2.0/24
#
# Flush the SAD and SPD
flush;
spdflush;

# I am gateway A (eth0:10.78.87.203, eth1:192.168.3.211)
#
# Security policies
spdadd 192.168.3.211 192.168.3.212 any -P out ipsec esp/tunnel/192.168.3.211-192.168.3.212/require;
spdadd 192.168.3.212 192.168.3.211 any -P in ipsec esp/tunnel/192.168.3.212-192.168.3.211/require;

spdadd 1.1.1.0/24 2.2.2.0/24 any -P out ipsec esp/tunnel/192.168.3.211-192.168.3.212/require;
spdadd 2.2.2.0/24 1.1.1.0/24 any -P in ipsec esp/tunnel/192.168.3.212-192.168.3.211/require;

# ESP SAs doing encryption using 192 bit long keys (168 + 24 parity)
# and hmac-sha1 authentication using 160 bit long keys
add 192.168.3.211 192.168.3.212 esp 0x201 -m tunnel
    -E aes-cbc  0x7aeaca3f87d060a12f4a4487d5a5c3355920fae69a96c831
    -A hmac-sha1 0xe9c43acd5e8d779b6e09c87347852708ab49bdd3;

add 192.168.3.212 192.168.3.211 esp 0x301 -m tunnel
    -E aes-cbc  0xf6ddb555acfd9d77b03ea3843f2653255afe8eb5573965df
    -A hmac-sha1 0xea6856479330dc9c17b8f6c37e2a895363d83f21;
