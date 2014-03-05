# OpenVAS Vulnerability Test
# $Id: punBB_install_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PunBB install.php XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "The remote web server contains a PHP application that is affected by
several cross-site scripting vulnerabilities. 

Description :

The remote version of PunBB is vulnerable to cross-site scripting
flaws through 'install.php' script.  With a specially-crafted URL, an
attacker can inject arbitrary HTML and script code into a user's
browser resulting in the possible theft of authentication cookies,
mis-representation of site contents, and the like.";

tag_solution = "Update to PunBB version 1.1.2 or later.";

if(description)
{
 script_id(15939);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(11845);
 script_xref(name:"OSVDB", value:"7976");

 name = "PunBB install.php XSS";

 script_name(name);
 script_tag(name:"cvss_base", value:"2.0");
 script_tag(name:"cvss_base_vector", value:"AV:R/AC:L/Au:N/C:P/A:N/I:N/B:N");
 script_tag(name:"risk_factor", value:"Low");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks for PunBB install.php XSS";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 family = "Web application abuses";
 script_family(family);
 script_dependencies("punBB_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.punbb.org/changelogs/1.1.1_to_1.1.2.txt");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (egrep(pattern: "^(0\.|1\.0|1\.1[^.]|1\.1\.1)",string:ver))
  {
    security_note(port);
    exit(0);
  }
}
