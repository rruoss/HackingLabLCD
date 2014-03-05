###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ManageEngine_ServiceDesk_Plus_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# ManageEngine ServiceDesk Plus Detection
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
tag_summary = "This host is running ManageEngine ServiceDesk Plus, a help desk
software.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(103183);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-06-29 13:12:40 +0200 (Wed, 29 Jun 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("ManageEngine ServiceDesk Plus Detection");

 script_description(desc);
 script_summary("Checks for the presence of ManageEngine ServiceDesk Plus");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.manageengine.com/products/service-desk/");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.103183";
SCRIPT_DESC = "ManageEngine ServiceDesk Plus Detection";

port = get_http_port(default:8080);

if(!get_port_state(port))exit(0);

url = string("/");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )continue;

if(egrep(pattern:"<title>ManageEngine ServiceDesk Plus</title>", string: buf, icase: TRUE))
{

   install=string("/");

   vers = string("unknown");
   ### try to get version 
   version = eregmatch(string: buf, pattern: "ManageEngine ServiceDesk Plus</a><span>&nbsp;&nbsp;\|&nbsp;&nbsp;([0-9.]+)",icase:TRUE);

   if ( !isnull(version[1]) ) {
      vers=chomp(version[1]);
      major = vers;
   }

   build = eregmatch(string: buf, pattern: "/scripts/Login\.js\?([0-9.]+)",icase:TRUE);

   if ( !isnull(build[1]) ) {
     vers=vers + string(" Build ", build[1]);
     BUILD = build[1];
   } else {
     BUILD = "unknown";
   }  

   set_kb_item(name: string("www/", port, "/ManageEngine"), value: string(vers," under ",install));
   
   if( ! isnull ( vers ) ) {
     register_host_detail(name:"App", value:string("cpe:/a:manageengine:servicedesk_plus:",major,":build_",BUILD), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
   } else {
     register_host_detail(name:"App", value:string("cpe:/a:manageengine:servicedesk_plus"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
   }  

   info = string("desk/\n\nManageEngine ServiceDesk Plus Version '");
   info += string(vers);
   info += string("' was detected on the remote host in the following directory(s):\n\n");
   info += string(install, "\n");

   desc = ereg_replace(
       string:desc,
       pattern:"desk/$",
       replace:info
   );

      if(report_verbosity > 0) {
        security_note(port:port,data:desc);
      }
      exit(0);

}

exit(0);

