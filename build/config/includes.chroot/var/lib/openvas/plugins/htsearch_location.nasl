# OpenVAS Vulnerability Test
# $Id: htsearch_location.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ht://Dig's htsearch reveals web server path
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# changes by rd : script id
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "ht://Dig's htsearch CGI can be 
used to reveal the path location of the its configuration files.
This allows attacker to gather sensitive information about the remote host.
For more information see:
http://www.securiteam.com/exploits/htDig_reveals_web_server_configuration_paths.html";

if(description)
{
 script_id(10385);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2000-1191");
 script_bugtraq_id(4366);
 name = "ht://Dig's htsearch reveals web server path";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Retrieve the real path using htsearch";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
  req = string(dir, "/htsearch?config=foofighter&restrict=&exclude=&method=and&format=builtin-long&sort=score&words=");
  req = http_get(item:req, port:port);
  result = http_keepalive_send_recv(port:port, data:req);
  if( result == NULL ) exit(0);
  
  if("ht://Dig error" >< result)
  {
   resultrecv = strstr(result, "Unable to read configuration file '");
   resultsub = strstr(resultrecv, string("foofighter.conf'\n"));
   resultrecv = resultrecv - resultsub;
   resultrecv = resultrecv - "Unable to read configuration file '";
   resultrecv = resultrecv - "foofighter.conf'\n";
   if ( ! resultrecv ) exit(0);

   banner = "ht://Dig's configuration file is located at: ";
   banner = banner + resultrecv;
   banner = banner + string("\n");

   security_warning(port:port, data:banner);
   exit(0);
  }
}
