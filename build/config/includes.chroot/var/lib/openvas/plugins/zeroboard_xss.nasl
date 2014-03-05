# OpenVAS Vulnerability Test
# $Id: zeroboard_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Zeroboard XSS
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
tag_summary = "The remote web server contains several PHP scripts that are prone to
cross-site scripting attacks. 

Description :

The remote host runs Zeroboard, a web BBS application popular in
Korea. 

The remote version of this software is vulnerable to cross-site
scripting attacks due to a lack of sanitization of user-supplied data. 
Successful exploitation of this issue may allow an attacker to execute
malicious script code in a user's browser within the context of the 
affected web site.";

tag_solution = "Upgrade to Zeroboard 4.1pl6 or later.";

# Ref: albanian haxorz

if(description)
{
  script_id(17199);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-0495");
  script_bugtraq_id(12596);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  
  script_name("Zeroboard XSS");

 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
  script_summary("Checks for Zeroboard XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/390933");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


if (thorough_tests) dirs = make_list("/bbs", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  req = http_get(item:string(dir, "/zboard.php?id=gallery&sn1=ALBANIAN%20RULEZ='%3E%3Cscript%3Efoo%3C/script%3E"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if( r == NULL )exit(0);

  if("<script>foo</script>" >< r )
  {
    security_warning(port);
    exit(0);
  }
}