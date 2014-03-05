###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_norman_security_suite_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Norman Security Suite Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
tag_summary = "Detection of Norman Security Suite.
                    
The script sends a connection request to the server and attempts to
detect Norman Security Suite from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103693";   

if (description)
{
 
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-04-10 13:55:18 +0200 (Wed, 10 Apr 2013)");
 script_name("Norman Security Suite Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Norman Security Suite");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 2868);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:2868);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: Norman Security/" >!< banner)exit(0);

vers = string("unknown");
install = port + '/tcp';

set_kb_item(name:"norman_security_suite/installed",value:TRUE);

cpe = 'cpe:/a:norman:security_suite';

register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

log_message(data: build_detection_report(app:"Norman Security Suite (Njeeves.exe)", version:vers, install:install, cpe:cpe, concluded: banner, extra:"Njeeves.exe, part of Norman Security Suite is running at this port."),
            port:port);

exit(0);
