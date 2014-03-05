# OpenVAS Vulnerability Test
# $Id: dotnetnuke_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Multiple DotNetNuke HTML Injection Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
tag_summary = "The remote host is running DotNetNuke, a portal written in ASP.

The remote software, according to its version number, contains several input 
validation flaws leading to the execution of attacker supplied HTML and script
code.";

tag_solution = "Upgrade to version 3.0.12 or greater";

if(description)
{
  script_id(18505);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-0040");
  script_bugtraq_id(13644, 13646, 13647);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
  script_name("Multiple DotNetNuke HTML Injection Vulnerabilities");
 
 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);

  script_summary("Checks version of DotNetNuke");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if(!can_host_asp(port:port))exit(0);

function check(url)
{
 req = http_get(item:url +"/default.aspx", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ( 'DotNetNukeAnonymous' >< res && egrep(pattern:"\( DNN (2\.0\.|2\.1\.[0-4]|3\.0\.([0-9]|1[0-1] \)))", string:res) )
 {
        security_warning(port);
        exit(0);
 }
}


foreach dir ( cgi_dirs() ) check(url:dir);
