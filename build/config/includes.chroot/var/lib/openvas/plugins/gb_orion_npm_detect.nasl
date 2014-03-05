###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orion_npm_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# SolarWinds Orion Network Performance Monitor Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Updated by : Antu Sanadi <santu@secpod.com> on 2011-09-15
#  Updated to detect for the sp versions
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
tag_summary = "This host is running SolarWinds Orion Network Performance Monitor
(NPM).";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 script_id(100940);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-12-09 13:44:03 +0100 (Thu, 09 Dec 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("SolarWinds Orion Network Performance Monitor Detection");

 script_description(desc);
 script_summary("Checks for the presence of SolarWinds Orion Network Performance Monitor");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8787);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.solarwinds.com/products/orion/");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:8787);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

dir = "/Orion";
url = string(dir, "/Login.aspx");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if( buf == NULL )continue;


if("SolarWinds Orion" >< buf || "Orion Network Performance Monitor" >< buf
   || "SolarWinds Orion Core" >< buf)
{
    if(strlen(dir)>0) {
       install=dir;
    } else {
       install=string("/");
    }

   vers = string("unknown");

   ### try to get version
   version = eregmatch(string: buf, pattern: "(NPM|Network Performance Monitor) (([0-9.]+).?([A-Z0-9]+)?)",icase:TRUE);
   if(!isnull(version[2]) ) {
      vers=chomp(version[2]);
   }

   set_kb_item(name: string("www/", port, "/orion_npm"), value: string(vers," under ",install));

   info = string("orion/\n\nSolarWinds Orion Network Performance Monitor Version '");
   info += string(vers);
   info += string("' was detected on the remote host in the following directory(s):\n\n");
   info += string(install, "\n");

   desc = ereg_replace(
       string:desc,
       pattern:"orion/$",
       replace:info
   );

   if(report_verbosity > 0) {
        security_note(port:port,data:desc);
   }
   exit(0);

}

exit(0);

