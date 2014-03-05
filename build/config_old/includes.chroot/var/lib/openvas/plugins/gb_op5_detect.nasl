###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_op5_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# OP5 Monitor Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_summary = "Detection of OP5 Monitor an monitoring system for IT infrastructure (http://www.op5.com/)";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103379";

if (description)
{

 script_oid(SCRIPT_OID);
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2012-01-09 10:33:57 +0100 (Mon, 09 Jan 2012)");
 script_tag(name:"detection", value:"remote probe");
 script_name("OP5 Monitor Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of OP5 Monitor");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = "/";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )continue;

if(egrep(pattern: "<title> Welcome to op5 Portal", string: buf, icase: TRUE))
{

   vers = string("unknown");
   ### try to get version 
   version = eregmatch(string: buf, pattern: 'Version: *([0-9.]+) *\\| *<a +href=".*/monitor"',icase:TRUE);

   if ( !isnull(version[1]) ) {
      vers=chomp(version[1]);
   }

   set_kb_item(name: string("www/", port, "/OP5"), value: string(vers," under /"));
   set_kb_item(name:"OP5/installed", value:TRUE);

   cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:op5:monitor:");
   if(isnull(cpe))
     cpe = 'cpe:/a:op5:monitor'; 

   register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:port);

   log_message(data: build_detection_report(app:"OP5 Monitor", version:vers, install:"/", cpe:cpe, concluded: version[0]),
               port:port);


}

exit(0);
