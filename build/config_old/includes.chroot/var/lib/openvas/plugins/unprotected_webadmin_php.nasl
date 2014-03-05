# OpenVAS Vulnerability Test
# $Id: unprotected_webadmin_php.nasl 17 2013-10-27 14:01:43Z jan $
# Description: webadmin.php detection
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
tag_summary = "webadmin.php was found on your web server. 
In its current configuration, this file manager CGI gives access 
to the whole filesystem of the machine to anybody.";

tag_solution = "Restrict access to this CGI or remove it";

if(description)
{
 script_id(18586);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_tag(name:"risk_factor", value:"High");

 script_name( "webadmin.php detection");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 script_summary( "Try to read /etc/passwd through webadmin.php");
 script_category(ACT_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 script_family( "Web application abuses");
 script_dependencies("find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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

if (get_kb_item('http/auth')) exit(0);	# CGI might be protected

port = get_http_port(default:80);

if (get_kb_item('/tmp/http/auth/'+port)) exit(0);	# CGI might be protected

foreach dir (cgi_dirs())
{
 req = http_get(port: port, item: dir + '/webadmin.php?show=%2Fetc%2Fpasswd');
 r = http_keepalive_send_recv(port: port, data: req, bodyonly: 0);
 if (r =~ '^HTTP/1\\.[01] 200 ')
 {
   debug_print(dir+'/webadmin.php?show=%2Fetc%2Fpasswd = ', r);
   if (egrep(string: r, pattern: '^root:.*:0:[01]:'))
   {
     log_print('Found ', dir+'/webadmin.php\n');
     security_hole(port);
     exit(0);
    }
  }
}

# res = is_cgi_installed_ka(port:port, item:"webadmin.php");
# if (res) security_warning(port);
