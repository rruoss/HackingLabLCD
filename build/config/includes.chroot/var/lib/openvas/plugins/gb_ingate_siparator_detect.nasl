###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ingate_siparator_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# inGate SIParator Detection
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
tag_summary = "This host is a inGate SIParator, a device that connects to an
existing network firewall to seamlessly enable SIP Communications.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(103206);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-08-17 15:40:19 +0200 (Wed, 17 Aug 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("inGate SIParator Detection");

 script_description(desc);
 script_summary("Checks for the presence of inGate SIParator");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.ingate.com/Products_siparators.php");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.103206";
SCRIPT_DESC = "inGate SIParator Detection";

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);

if(!banner || "Server: Ingate-SIParator/" >!< banner)exit(0); 

vers = "unknown";
version = eregmatch(pattern:"Server: Ingate-SIParator/([0-9.]+)",string:banner);

if(!isnull(version[1]))vers = version[1];

set_kb_item(name:string(port,"/Ingate_SIParator"),value:vers);

if(vers == "unknown") {
  register_host_detail(name:"App", value:string("cpe:/h:ingate:siparator"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
} else {
  register_host_detail(name:"App", value:string("cpe:/h:ingate:siparator:",vers), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}  

desc = string(desc,"\n\ninGate SIParator version '",vers,"' was detected.\n");

security_note(port:port,data:desc);

exit(0);

