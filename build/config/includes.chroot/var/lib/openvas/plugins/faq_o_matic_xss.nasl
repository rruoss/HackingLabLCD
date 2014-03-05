# OpenVAS Vulnerability Test
# $Id: faq_o_matic_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Faq-O-Matic fom.cgi XSS
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
tag_summary = "The remote host runs Faq-O-Matic, a CGI-based system that automates 
the process of maintaining a FAQ.

The remote version of this software is vulnerable to cross-site scripting 
attacks in the script 'fom.cgi'.

With a specially crafted URL, an attacker can cause arbitrary code 
execution resulting in a loss of integrity.";

tag_solution = "Upgrade to the latest version of this software";

# Ref: superpetz <superpetz@hushmail.com>

if(description)
{
  script_id(15540);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4565);
  script_cve_id("CVE-2002-0230", "CVE-2002-2011");
  script_xref(name:"OSVDB", value:"8661");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
  script_name("Faq-O-Matic fom.cgi XSS");
 
 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);

  script_summary("Checks Faq-O-Matic XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("cross_site_scripting.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");


function check(req)
{
  buf = http_get(item:string(req,"/fom/fom.cgi?cmd=<script>foo</script>&file=1&keywords=openvas"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	exit(0);
  }
}

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port)) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
foreach dir (cgi_dirs()) check(req:dir);
exit(0);
