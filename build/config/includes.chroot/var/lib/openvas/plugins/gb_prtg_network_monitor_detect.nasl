###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_prtg_network_monitor_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# PRTG Network Monitor Detection
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
tag_summary = "This host is running the PRTG Network Monitor.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(103048);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-27 12:55:42 +0100 (Thu, 27 Jan 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("PRTG Network Monitor Detection");

 script_description(desc);
 script_summary("Checks for the presence of PRTG Network Monitor");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.paessler.com/prtg");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:8081);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: PRTG/" >!< banner)exit(0);

url = string("/index.htm");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )continue;

if(egrep(pattern: "PRTG Network Monitor", string: buf, icase: TRUE))
{

   install=string("/");

   vers = string("unknown");
   ### try to get version 
   version = eregmatch(string: buf, pattern: "Server: PRTG/([0-9.]+)",icase:TRUE);

   if ( !isnull(version[1]) ) {
      vers=chomp(version[1]);
   }

   set_kb_item(name: string("www/", port, "/prtg_network_monitor"), value: string(vers," under ",install));

   info = string("prtg\n\nPRTG Network Monitor Version '");
   info += string(vers);
   info += string("' was detected on the remote host in the following directory(s):\n\n");
   info += string(install, "\n");

   desc = ereg_replace(
       string:desc,
       pattern:"prtg$",
       replace:info
   );

      if(report_verbosity > 0) {
        security_note(port:port,data:desc);
      }
      exit(0);

}

exit(0);

