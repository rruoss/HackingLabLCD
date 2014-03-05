# OpenVAS Vulnerability Test
# $Id$
# Description: functions to support sip
#
# Authors:
# Ferdy Riphagen <f.riphagen@nsec.nl>
#
# Copyright:
# Copyright (C) 2007 Ferdy Riphagen <f.riphagen@nsec.nl>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 1.0 $
# Experimental!

#--------------------------------------------------------#
# function get_sip_banner:                               #
#     Some function code taken from 'sip_detection.nasl' #
#     (C) 2006 Josh Zlatin-Amishav and Ferdy Riphagen    #
#--------------------------------------------------------#

function get_sip_banner(port) {
    local_var soc, opt, r, banner;
    global_var port;

    banner = get_kb_item(strcat("sip/banner/", port));
    if (banner) return banner; 

    if (islocalhost()) soc = open_sock_udp(port);
    else soc = open_priv_sock_udp(sport:5060, dport:port);
    if (!soc) return NULL;

    opt = string(
        "OPTIONS sip:", get_host_name(), " SIP/2.0", "\r\n",
        "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
        "Max-Forwards: 70\r\n",
        "To: <sip:", this_host(), ":", port, ">\r\n",
        "From: OpenVAS <sip:", this_host(), ":", port, ">\r\n",
        "Call-ID: ", rand(), "\r\n",
        "CSeq: 63104 OPTIONS\r\n",
        "Contact: <sip:", this_host(), ">\r\n",
        "Accept: application/sdp\r\n",
        "Content-Length: 0\r\n\r\n");

    send(socket:soc, data:opt);
    r = recv(socket:soc, length:1024);

    if ("SIP/2.0" >< r && ("Server:" >< r)) {
        banner = egrep(pattern:'^Server:', string:r);
        banner = substr(banner, 8);
    }
    else if ("SIP/2.0" >< r && ("User-Agent" >< r)) {
        banner = egrep(pattern:'^User-Agent', string:r);
        banner = substr(banner, 12);
    }

    if (!isnull(banner)) return banner;
    else return NULL;
}


#--------------------------------------------------------#
# function sip_send_recv:                                #
#     Send self modified SIP packets                     #        
#     returns received packets                           #
#--------------------------------------------------------#

function sip_send_recv(port, data) {
    local_var ret, soc;
    global_var port, data;

    if (islocalhost()) soc = open_sock_udp(port);
    else soc = open_priv_sock_udp(sport:5060, dport:port);
    if (!soc) return NULL;

    if (soc) {
        send(socket:soc, data:data);
        ret = recv(socket:soc, length:1024);
        if (!isnull(ret)) return ret;
    }
    return NULL;
}

