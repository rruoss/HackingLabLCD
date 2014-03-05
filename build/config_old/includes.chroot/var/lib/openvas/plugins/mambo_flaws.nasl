# OpenVAS Vulnerability Test
# $Id: mambo_flaws.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Mambo Site Server XSS and remote arbitrary code execution
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# Updated: 04/07/2009 Antu Sanadi <santu@secpod.com>
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
tag_summary = "An attacker may use the installed version of Mambo Site Server to
  perform a cross site scripting attack on this host or execute arbitrary
  code through the gallery image uploader under the administrator
  directory.";

tag_solution = "Upgrade to the latest version of this software.";

#  Ref: Mindwarper <mindwarper at hush.com>

if (description)
{
  script_id(16315);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1204");
  script_bugtraq_id(6571, 6572);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Mambo Site Server XSS and remote arbitrary code execution");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
  script_summary("Determine if Mambo Site Server is vulnerable to xss attack and remote flaw");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_dependencies("mambo_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/306206");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

version=get_kb_item(string("www/", port, "/mambo_mos"));
if(!version){
   exit(0);
}

matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$");
if(!matches){
  exit(0);
}

 dir = matches[2];
 url = string(dir, "/themes/mambosimple.php?detection=detected&sitename=</title><script>foo</script>");
 req = http_get(item:url, port:port);
 resp = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( !resp){
   exit(0);
 }

if('<a href="?detection=detected&sitename=</title><script>foo</script>' >< resp )
    security_hole(port);

