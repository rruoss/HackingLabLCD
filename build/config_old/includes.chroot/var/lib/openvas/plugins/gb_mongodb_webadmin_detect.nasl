###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_webadmin_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# MongoDB Web Admin Detection
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
tag_summary = "MongoDB Web Admin is running at this port.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(100748);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-06 15:09:20 +0200 (Fri, 06 Aug 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("MongoDB Web Admin Detection");
 
 script_description(desc);
 script_summary("Checks for the presence of MongoDB Web Admin");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","http_version.nasl","gb_mongodb_detect.nasl");
 script_require_keys("mongodb/installed");
 script_require_ports("Services/www", 28017);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.mongodb.org/");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if(!get_kb_item(string("mongodb/installed")))exit(0);

port = get_http_port(default:28017);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server:" >< banner)exit(0);

url = string("/");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )continue;

if(("title>mongodb" >< buf && "db version" >< buf) || ("unauthorized db:admin lock type" >< buf)) {

  if("db version" >< buf) {
    version = eregmatch(pattern:"db version v([0-9.]+),", string:buf);
    if(!isnull(version[1])) {
      vers = version[1];

      info = string("/\n\nMongoDB Version '");
      info += string(vers);
      info += string("' Web Admin was detected on the remote host\n");

      set_kb_item(name:string("mongodb/webadmin/version"),value: vers);

      desc = ereg_replace(
          string:desc,
          pattern:"/$",
          replace:info
      );
    }    
  }

  if(report_verbosity > 0) {
    security_note(port:port,data:desc);
  }
  exit(0);
}

exit(0);
