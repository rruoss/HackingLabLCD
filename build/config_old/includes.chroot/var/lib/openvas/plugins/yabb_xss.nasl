# OpenVAS Vulnerability Test
# $Id: yabb_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: YaBB XSS and Administrator Command Execution
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Fixes by Tenable:
#   - added CVE xrefs.
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
tag_summary = "The remote web server contains a CGI application that suffers from
multiple vulnerabilities. 

Description :

The 'YaBB.pl' CGI is installed.  This version is affected by a
cross-site scripting vulnerability.  This issue is due to a failure of
the application to properly sanitize user-supplied input. 

As a result of this vulnerability, it is possible for a remote
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. 

Another flaw in YaBB may allow an attacker to execute malicious
administrative commands on the remote host by sending malformed IMG
tags in posts to the remote YaBB forum and waiting for the forum
administrator to view one of the posts.";

tag_solution = "Unknown at this time.";

#  Ref: GulfTech Security <security@gulftech.org>

if(description)
{
 script_id(14782);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2402", "CVE-2004-2403");
 script_bugtraq_id(11214, 11215);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "YaBB XSS and Administrator Command Execution";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks YaBB.pl XSS";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
		
 family = "Web application abuses";
 script_family(family);
 script_dependencies("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2004-09/0227.html");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if (!get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if (thorough_tests) dirs = make_list("/yabb", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (cgi_dirs())
{
 req = string(dir, "/YaBB.pl?board=;action=imsend;to=%22%3E%3Cscript%3Efoo%3C/script%3E");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if (egrep(pattern:"<script>foo</script>", string:r))
 {
       security_hole(port);
       exit(0);
 }
}
