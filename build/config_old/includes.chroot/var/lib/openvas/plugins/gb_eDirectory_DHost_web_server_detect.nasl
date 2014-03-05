###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eDirectory_DHost_web_server_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# eDirectory DHost Web Server Detection
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
tag_summary = "The eDirectory DHost web server is running at this port.";

if (description)
{
 
 script_id(103125);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-23 13:28:27 +0100 (Wed, 23 Mar 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("eDirectory DHost Web Server Detection");

 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 script_summary("Checks for the presence of eDirectory DHost Web Server");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8028,8030);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:8028);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(banner !~ "Server: DHost/[0-9.]+ HttpStk")exit(0);

url = string("/");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )exit(0);

if("DHost Console" >< buf && "DS Trace" >< buf && "NDS iMonitor" >< buf) {

  set_kb_item(name: string("www/", port, "/eDirectory_DHost"), value: TRUE);

  if(report_verbosity > 0) {
    security_note(port:port,data:desc);
  }

  exit(0);

}

exit(0);

