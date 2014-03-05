# OpenVAS Vulnerability Test
# $Id: lotus_domino_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Lotus Domino Src and BaseTarget XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote web server is vulnerable to cross-site scripting issues.

Description :

The remote host runs Lotus Domino web server.

This version is vulnerable to multiple cross-site scripting due to a
lack of sanitization of user-supplied data.  Successful exploitation of
this issue may allow an attacker to execute malicious script code in a
user's browser within the context of the affected application.";

tag_solution = "Upgrade to Domino 6.5.2 or newer";

if(description)
{
  script_id(19764);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3015");
  script_bugtraq_id(14845, 14846);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  
  script_name("Lotus Domino Src and BaseTarget XSS");

 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
  script_summary("Checks Lotus Domino XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
if ( "Lotus" >!< banner ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

buf = http_get(item:"/", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

matches = egrep(pattern:'src=.+(.+?OpenForm.+BaseTarget=)', string:r);
foreach match (split(matches)) 
{
       match = chomp(match);
       matchspec=eregmatch(pattern:'src="(.+?OpenForm.+BaseTarget=)', string:match);
       if (!isnull(matchspec))
       {
	       buf = http_get(item:string(matchspec[1],'";+<script>alert(foo)</script>;+var+mit="a'), port:port);
	       r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
	       if( r == NULL )exit(0);

	       if ("<script>alert(foo)</script>" >< r)
	       {
		       security_warning(port);
	       }
       }
}
exit(0);
