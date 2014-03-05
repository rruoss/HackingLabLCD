# OpenVAS Vulnerability Test
# $Id: upb_weak_pass.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Ultimate PHP Board users.dat Information Disclosure
#
# Authors:
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
# Fixes by Tenable:
#   - removed '/upb' from first request string so test is not dependent
#     on a specific installation directory.
#   - actually tested for users.dat content rather than the response code.
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
tag_summary = "The remote host is running Ultimate PHP Board (UPB).

The remote version of this software is prone to a weak password encryption
vulnerability and may store the users.dat file under the web document root
with insufficient access control.";

tag_solution = "Unknown at this time.";

if(description)
{
 script_id(19497);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2005-2005", "CVE-2005-2030");
 script_bugtraq_id(13975);
 script_xref(name:"OSVDB", value:"17374");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "Ultimate PHP Board users.dat Information Disclosure";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Tries to get the users.dat file and checks UPB version";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://securityfocus.com/archive/1/402506");
 script_xref(name : "URL" , value : "http://securityfocus.com/archive/1/402461");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 # First try to get users.dat
 req = http_get(
   item:string(
     dir, "/db/users.dat"
   ),
   port:port
 );


 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 # nb: records look like:
 #     user_name<~>password<~>level<~>email<~>view_email<~>mail_list<~>location<~>url<~>avatar<~>icq<~>aim<~>msn<~>sig<~>posts<~>date_added<~>id
 if ( egrep(string:res, pattern:"<~>20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]<~>[0-9]+$") )
 {
        security_hole(port);
        exit(0);
 }

 # See if the version is known to be vulnerable.
 req = http_get(
   item:string(
     dir, "/index.php"
   ),
   port:port
 );


 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( egrep(pattern:"Powered by UPB Version : 1\.([0-8]|9\.[0-6])", string:res) )
 {
        security_warning(port);
        exit(0);
 }
}
