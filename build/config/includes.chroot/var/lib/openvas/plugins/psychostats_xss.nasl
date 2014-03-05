# OpenVAS Vulnerability Test
# $Id: psychostats_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PsychoStats Login Parameter Cross-Site Scripting
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "PsychoStats is a statistics generator for games. Currently there is support 
for a handful of Half-Life 'MODs' including Counter-Strike, Day of Defeat, 
and Natural Selection.

There is a bug in this software which makes it vulnerable to HTML and 
JavaScript injection. An attacker may use this flaw to use the remote
server to set up attacks against third-party users.";

tag_solution = "Upgrade to the newest version of this software.";

# Cross Site Scripting In PsychoStats 2.2.4 Beta && Earlier
# "GulfTech Security" <security@gulftech.org>
# 2004-12-23 02:50

if(description)
{
 script_id(16057);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2004-1417");
 script_bugtraq_id(12089);
 
 name = "PsychoStats Login Parameter Cross-Site Scripting";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence of a PsychoStats XSS";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

function check(loc)
{
 req = http_get(item: string(loc, "/login.php?login=<script>foo</script>"), port:port);
 
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if('"login" value="<script>foo</script>' >< r)
 {
  security_warning(port);
  exit(0);
 }
}

check(loc:"/");

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
