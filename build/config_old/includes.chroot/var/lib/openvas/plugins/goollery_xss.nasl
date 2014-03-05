# OpenVAS Vulnerability Test
# $Id: goollery_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Goollery Multiple XSS
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
tag_summary = "Goollery, a GMail based photo gallery written in PHP, 
is installed on this remote host.

According to it's version number, this host is vulnerable to multiple
cross-site-scripting (XSS) attacks; eg, through the 'viewpic.php'
script.  An attacker, exploiting these flaws, would need to be able to
coerce a user to browse a malicious URI.  Upon successful exploitation,
the attacker would be able to run code within the web-browser in the
security context of the remote server.";

tag_solution = "Upgrade to Goollery 0.04b or newer.";

# Ref: Lostmon <lostmon@gmail.com>

if(description)
{
 script_id(15717);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2245");
 script_bugtraq_id(11587);
 script_xref(name:"OSVDB", value:"11318");
 script_xref(name:"OSVDB", value:"11319");
 script_xref(name:"OSVDB", value:"11320");
 script_xref(name:"OSVDB", value:"11624");
 
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "Goollery Multiple XSS";
 script_name(name);
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence of Goollery XSS flaw in viewpic.php ";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 family = "Web application abuses";
  script_family(family);
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

function check(loc)
{
 	req = http_get(item:string(loc, "/viewpic.php?id=7&conversation_id=<script>foo</script>&btopage=0"),
 		port:port);			
 	r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 	if( r == NULL )
		exit(0);
 	if(egrep(pattern:"<script>foo</script>", string:r))
 	{
 		security_warning(port);
		exit(0);
 	}
}

dir = make_list(cgi_dirs(),"/goollery");
foreach d (dir)	
{
 	check(loc:d);
}
