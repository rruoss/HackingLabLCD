# OpenVAS Vulnerability Test
# $Id: asterisk_pbx_guest_access_enabled.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Asterisk PBX SIP Service Guest Access Enabled
#
# Authors:
# Ferdy Riphagen 
# Fix by George A. Theall when the system answers the call
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
tag_summary = "Asterisk PBX SIP service guest access is enabled.

Description :

Asterisk an open-source PBX is installed on the remote system. 
The SIP service is accepting SIP peers to use the proxy server
as guest users. Unauthenticated users can use the proxy
without supplying the required 'more secure' authentication. 

Guest access is enabled by default if 'allowguest=no' is not set
in 'sip.conf'. Guest peers use the context defined under the
general section and the restrictions set in the Asterisk config
files.";

tag_solution = "If guest access is not needed, disable it by setting 'allowguest=no'
in the sip.conf file.";

if (description) {
 script_id(9999993);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
 script_tag(name:"cvss_base", value:"3.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "Asterisk PBX SIP Service Guest Access Enabled";
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_name(name);
 summary = "Detect if it is possible for guest access to the Asterisk PBX SIP service";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2007 Ferdy Riphagen");
 
 script_dependencies("sip_detection.nasl");
 script_require_keys("Services/udp/sip");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.voip-info.org/wiki/index.php?page=Asterisk+sip+allowguest");
 exit(0);
}

function sip_send_recv(port, data) {
    local_var r, soc;
    global_var port, data;

    soc = open_priv_sock_udp(sport:5060, dport:port);
    if (!soc) return NULL;

    send(socket:soc, data:data);
    r = recv(socket:soc, length:1024);
    if (!isnull(r)) return r;
    return NULL;
}

if (islocalhost()) exit(0);
port = get_kb_item("Services/udp/sip");
if (!port) port = 5060;

banner = get_kb_item(strcat("sip/banner/", port));
if ("Asterisk PBX" >!< banner) exit(0);

rpeer = string("NotExistingPeer", rand() %900 +100, "@");
lpeer = string("OpenVAS", rand() %900 +100, "@");

invite = string(
    "INVITE sip:", rpeer, get_host_name(), " SIP/2.0", "\r\n",
    "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
    "To: <sip:", rpeer, get_host_name(), ":", port, ">\r\n",
    "From: <sip:", lpeer, this_host(), ":", sport, ">\r\n",
    "Call-ID: ", rand(), "\r\n",
    "CSeq: ", rand(), " INVITE\r\n",
    "Contact: <sip:", lpeer, this_host(), ">\r\n",
    "Content-Length: 0\r\n\r\n");

res = sip_send_recv(port:port, data:invite);
if (isnull(res)) exit(0);

if ("SIP/2.0 404 Not Found" >< res ||
   ("SIP/2.0 100 Trying" >< res)) {
    set_kb_item(name:"sip/guest_access/" + port, value:"yes");
    security_warning(port);
}
