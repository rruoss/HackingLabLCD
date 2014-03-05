###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ingate_firewall_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# inGate Firewall Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "This host is a inGate Firewall.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{

 script_id(103207);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-08-17 15:40:19 +0200 (Wed, 17 Aug 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("inGate Firewall Detection");

 script_description(desc);
 script_summary("Checks for the presence of inGate Firewall");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("sip_detection.nasl");
 script_require_udp_ports("Services/udp/sip");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.ingate.com/Products_firewalls.php");
 exit(0);
}

include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.103207";
SCRIPT_DESC = "inGate Firewall Detection";


port = get_kb_item("Services/udp/sip");
if (!port) port = 5060;
if(!(get_udp_port_state(port)))exit(0);

banner =  get_kb_item(string("sip/banner/",port));
if(!banner || "Ingate-Firewall/" >!< banner)exit(0);

vers = "unknown";

version = eregmatch(pattern:"Ingate-Firewall/([0-9.]+)", string:banner);
if(!isnull(version[1])) vers = version[1];

set_kb_item(name:string(port,"/Ingate_Firewall"),value:vers);

if(vers == "unknown") {
  register_host_detail(name:"App", value:string("cpe:/h:ingate:ingate_firewall"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
} else {
  register_host_detail(name:"App", value:string("cpe:/h:ingate:ingate_firewall:",vers), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

desc = string(desc,"\n\ninGate Firewall version '",vers,"' was detected.\n");

security_note(port:port,data:desc);

exit(0);

 
  
