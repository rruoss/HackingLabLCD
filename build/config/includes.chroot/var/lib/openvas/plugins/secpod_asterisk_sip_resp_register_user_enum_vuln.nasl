###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_asterisk_sip_resp_register_user_enum_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Asterisk SIP REGISTER Response Username Enumeration Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to obtain valid username that
  could aid in further attacks.
  Impact Level: Application";
tag_affected = "Asterisk Business Edition C.3.x
  Asterisk Open Source Version 1.4.x, 1.6.2.x, 1.8.x";
tag_insight = "The problem is that different responses are being sent when using a valid or
  an invalid username in REGISTER messages. This can be exploited to determine
  valid usernames by sending specially crafted REGISTER messages.";
tag_solution = "Please refer below link for updates,
  http://downloads.asterisk.org/pub/security/AST-2011-011.html";
tag_summary = "This host is running Asterisk Server and is prone to username
  enumeration vulnerability.";

if(description)
{
  script_id(900293);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Asterisk SIP REGISTER Response Username Enumeration Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/73257");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44707");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101720");
  script_xref(name : "URL" , value : "http://downloads.asterisk.org/pub/security/AST-2011-011.html");

  script_description(desc);
  script_summary("Determine Asterisk Server is prone to Username Enumeration Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_require_keys("Services/udp/sip");
  script_require_udp_ports(5060);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

##
## The script code starts here
##

## Get SIP Port
asterisk_port = get_kb_item("Services/udp/sip");
if(!asterisk_port){
  asterisk_port = 5060;
}

## Check Port State
if(!get_udp_port_state(asterisk_port)){
  exit(0);
}

## Create UDP Soc
udp_soc = open_sock_udp(asterisk_port);

## Construct "REGISTER" request with invalid user
craf_req = string( "REGISTER sip:", get_host_name(), " SIP/2.0", "\r\n",
                   "CSeq: 123 REGISTER", "\r\n",
                   "Via: SIP/2.0/UDP ", this_host(), ":", asterisk_port ,
                       " ;branch=z9hG4bK78adb2cd-0671-e011-81a1-a1816009ca7a",
                                                             ";rport", "\r\n",
                   "User-Agent: BSTest", "\r\n",
                   "From: <sip:bstestenumtest@", get_host_name(), ">;tag=642d",
                                   "29cd-0671-e011-81a1-a1816009ca7a", "\r\n",
                   "Call-ID: 2e2f07e0499cec3abf7045ef3610f0f2", "\r\n",
                   "To: <sip:bstestenumtest@", get_host_name(), ">", "\r\n",
                   "Refer-To: sip:bstestenumtest@", get_host_name(), "\r\n",
                   "Contact: <sip:bstestenumtest@", this_host(), " >;q=1\r\n",
                   "Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,",
                                            "REFER,MESSAGE,INFO,PING", "\r\n",
                   "Expires: 3600", "\r\n",
                   "Content-Length: 28000", "\r\n",
                   "Max-Forwards: 70", "\r\n",
                   "\r\n"
                );

## Send request  and Receive response
send(socket:udp_soc, data:craf_req);
res = recv(socket:udp_soc, length:1024);

## Confirm the application and check it's vulnerable or not
if("Server: Asterisk" >< res && res =~ "SIP\/[0-9].[0-9] 100 Trying"){
  security_warning(asterisk_port);
}
