#!/usr/sbin/setkey -f
#
#
# Example ESP Tunnel for VPN.
#                                        gateway A<============ESP===========>
#          LAN          	  VM-eth0           VM-eth1                   Gateway-B
#         10.78.87.0/24 ==== 10.78.87.203 -- 192.168.3.211 ============== 192.168.3.212
#
# Flush the SAD and SPD
flush;
spdflush;

