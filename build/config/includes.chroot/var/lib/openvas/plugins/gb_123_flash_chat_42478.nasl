###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_123_flash_chat_42478.nasl 14 2013-10-27 12:33:37Z jan $
#
# 123 Flash Chat Multiple Security Vulnerabilities
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
tag_summary = "123 Flash Chat is prone to multiple security vulnerabilities. These
vulnerabilities include a cross-site scripting vulnerability, multiple
information-disclosure vulnerabilities, and a directory-traversal
vulnerability.

An attacker can exploit these vulnerabilities to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, steal cookie-based authentication credentials,
obtain sensitive information, or perform unauthorized actions. Other
attacks are also possible.

123 Flash Chat 7.8 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100766);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-31 14:30:50 +0200 (Tue, 31 Aug 2010)");
 script_bugtraq_id(42478);

 script_name("123 Flash Chat Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42478");
 script_xref(name : "URL" , value : "http://123flashchat.com/");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if 23 Flash Chat is prone to multiple security vulnerabilities.");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 35555);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:35555);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: TopCMM Server" >!< banner)exit(0);

url = string("/index.html%27%22--%3E%3Cscript%3Ealert%28%27openvas-xss-test%27%29%3C/script%3E"); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('openvas-xss-test'\)</script>",extra_check:"Error Information")) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);
