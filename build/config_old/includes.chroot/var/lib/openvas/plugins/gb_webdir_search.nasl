###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webdir_search.nasl 12 2013-10-27 11:15:33Z jan $
#
# Search for specified webdirs
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
tag_summary = "This Plugin is searching for the specified webdirs.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103437";   

if (description)
{
 
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-27 16:32:37 +0100 (Mon, 27 Feb 2012)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Search for specified dirs");

 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 script_summary("Checks for the presence of specified webdirs");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl","no404.nasl");
 script_require_ports("Services/www", 80);

 script_add_preference(name: "Severity", type:"radio", value:"High;Medium;Low");
 script_add_preference(name: "Search for dir(s)", value: "/admin;/manager", type: "entry");
 script_add_preference(name: "Valid http status codes indicating that a directory was found", value: "200;301;302;401;403", type: "entry");
 script_add_preference(name: "Run this Plugin", type:"checkbox", value: "no");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

run  = script_get_preference("Run this Plugin");
if("yes" >!< run)exit(0);

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(get_kb_item("www/no404/" + port)) {
  exit(0);
}  

function check_response(resp) {

  local_var resp,code;

  foreach code (codes) {

    if(!isnull(code)) {
      if(ereg(pattern:"HTTP/1\.[0|1] " + code, string:resp)) {
        return TRUE;
      }
    }  

  }

  return FALSE;

}  

severity      = script_get_preference("Severity");
search_dirs   = script_get_preference("Search for dir(s)");
http_codes    =  script_get_preference("Valid http status codes indicating that a directory was found"); 

dirs = split(search_dirs, sep:";", keep:FALSE);
if(max_index(dirs) < 1)exit(0);

codes = split(http_codes, sep:";", keep:FALSE);
if(max_index(codes) < 1)exit(0);

foreach dir (dirs) {

 dir = chomp(dir);

 if(!ereg(pattern: "^/", string: dir)) dir = "/" + dir;

 req = http_get(item:dir, port:port);
 buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL || buf =~ "HTTP/1\.[0|1] 404")continue;

 if(check_response(resp:buf)) {
   report += 'Found dir ' + dir + '\n';
 }  

}

if(report) {

  if(severity == "Low") {
    security_note(port:port,data:report);
    exit(0);
  }
  else if(severity == "Medium") {
    security_warning(port:port,data:report);
    exit(0);
  }
  else if(severity == "High") {
    security_hole(port:port,data:report);
    exit(0);
  }

}  

exit(0);

