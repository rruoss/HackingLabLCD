# OpenVAS Vulnerability Test
# $Id: osCommerce_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: osCommerce Cross Site Scripting Bugs
#
# Authors:
# K-Otik.com <ReYn0@k-otik.com>
# Ref added by rd
#
# Copyright:
# Copyright (C) 2003 k-otik.com
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
tag_summary = "osCommerce is a widely installed open source shopping e-commerce solution.
An attacker may use it to perform a cross site scripting attack on
this host.";

tag_solution = "Upgrade to a newer version.";

#  Message-ID: <009e01c2eef9$069683b0$0900a8c0@compcaw8>
#  From: Daniel Alcántara de la Hoz <seguridad@iproyectos.com>
#  To: <bugtraq@securityfocus.com>
#  Subject: [IPS] osCommerce multiple XSS vulnerabilities

if (description)
{
 script_id(11437);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(7151, 7153, 7155, 7156, 7158);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("osCommerce Cross Site Scripting Bugs");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_xref(name : "URL" , value : "http://secunia.com/advisories/8368/");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/11590");
 script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1006342");

 script_description(desc);
 script_summary("Determine if osCommerce is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2003 k-otik.com");
 script_dependencies("oscommerce_detect.nasl", "cross_site_scripting.nasl");
 script_require_keys("Software/osCommerce");
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
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port)) exit(0);

dir = get_kb_list("Software/osCommerce/dir");

foreach d (dir)
{
 url = string(d, "/default.php?error_message=<script>window.alert(document.cookie);</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:buf) &&
    "<script>window.alert(document.cookie);</script>" >< buf)
   {
    security_warning(port:port);
    exit(0);
   }
}
