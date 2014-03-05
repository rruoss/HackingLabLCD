###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_coldfusion_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# ColdFusion Detection
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
tag_summary = "Detection of ColdFusion.

The script sends a connection request to the server and attempts to
check the presence of ColdFusion from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100773";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("ColdFusion Detection");
 script_tag(name:"detection", value:"remote probe");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);

 script_summary("Checks for the presence of ColdFusion");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = "/CFIDE/administrator/index.cfm";

if(http_vuln_check(port:port, url:url,pattern:"<title>ColdFusion Administrator Login</title>")) {
  CF_FOUND = TRUE;
} else {
  banner = get_http_banner(port:port);
  if("X-Powered-By: ColdFusion" >< banner || "XPoweredBy: ColdFusion" >< banner || "X-Custom-Header: Coldfusion" >< banner ) CF_FOUND = TRUE;
}  

if(CF_FOUND) {
  cpe = 'cpe:/a:adobe:coldfusion';
  location = string(port, "/http");
  register_product(cpe:cpe, location:location, nvt:SCRIPT_OID, port:port);
  set_kb_item(name: string("coldfusion/",port,"/installed"), value: TRUE);
  set_kb_item(name: string("coldfusion/installed"), value: TRUE);

  log_message(data: build_detection_report(app:"Adobe ColdFusion",
                    version: "Unknown", install: location, cpe:cpe,
                    concluded: "Remote probe"), port: port);
}  
