# OpenVAS Vulnerability Test
# $Id: squirremail_cross_site_scripting.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SquirrelMail's Cross Site Scripting
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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
tag_summary = "The remote host seems to be vulnerable to a security problem in
SquirrelMail. Its script 'read_body.php' didn't filter out user input for
'filter_dir' and 'mailbox', making a xss attack possible.";

tag_solution = "Upgrade to a newer version of this software";

# Did not really check CVE-2002-1276, since it`s the same kind of problem.

if (description)
{
 script_id(11415);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(6302, 7019);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2002-1276", "CVE-2002-1341");
 script_xref(name:"RHSA", value:"RHSA-2003:0042-07");

 script_name("SquirrelMail's Cross Site Scripting");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 script_summary("Determine if a remote host is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
 script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);


check1 = string("<script>alert(document.cookie)</script>");
check2 = string("%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E");

foreach d (cgi_dirs())
{
 url = string(d, "/read_body.php");
 data = string(url, "?mailbox=",
"<script>alert(document.cookie)</script>&passed_id=",
"<script>alert(document.cookie)</script>&",
"startMessage=1&show_more=0");
 req = http_get(item:data, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf))exit(0);
 if (check1 >< buf)
   {
    security_hole(port:port);
    exit(0);
   }
# if (check2 >< buf)
#   {
#    security_hole(port:port);
#    exit(0);
#   }
}
