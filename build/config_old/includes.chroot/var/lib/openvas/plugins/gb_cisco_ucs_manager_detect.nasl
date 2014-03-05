###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ucs_manager_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Cisco UCS Manager Detection
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103804";   

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"detection", value:"remote probe");
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-10 18:42:38 +0200 (Thu, 10 Oct 2013)");
 script_name("Cisco UCS Manager Detection");

 tag_summary =
"The script sends a connection request to the server and attempts to
extract the version number from the reply.";

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Checks for the presence of Cisco UCS Manager");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }

 exit(0);
}

include("http_func.inc");
include("openvas-https.inc");
include("host_details.inc");

port = get_http_port(default:443);
if(!get_port_state(port))exit(0);

url = '/';
req = http_get(item:url, port:port);
buf = https_req_get(port:port, request:req);

if("<title>Cisco UCS Manager</title>" >!< buf || "UCS Manager requires Java" >!< buf)exit(0);

vers = 'unknown';

version = eregmatch(pattern:'<p class="version">Version ([^<]+)</p>', string:buf);
if(isnull(version[1]))
  version = eregmatch(pattern:'<h1>Cisco UCS Manager - ([^<]+)</h1>', string:buf);

if(!isnull(version[1])) vers = version[1];

set_kb_item(name:"cisco_ucs_manager/installed",value:TRUE);

if(vers != 'unknown')
 cpe = 'cpe:/a:cisco:unified_computing_system_software:' + vers;
else
 cpe = 'cpe:/a:cisco:unified_computing_system_software';

register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:port);

log_message(data: build_detection_report(app:"Cisco UCS Manager", version:vers,install:"/",cpe:cpe,concluded: version[0]), 
            port:port);

exit(0);

