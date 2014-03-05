###############################################################################
# OpenVAS Vulnerability Test
# $Id: minihttpd_and_thttpd_webserver_37714.nasl 14 2013-10-27 12:33:37Z jan $
#
# Acme thttpd and mini_httpd Terminal Escape Sequence in Logs Command Injection Vulnerability
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
tag_summary = "Acme 'thttpd' and 'mini_httpd' are prone to a command-injection
vulnerability because they fail to adequately sanitize user-supplied
input in logfiles.

Attackers can exploit this issue to execute arbitrary commands in
a terminal.

This issue affects thttpd 2.25b and mini_httpd 1.19; other versions
may also be affected.";


if (description)
{
 script_id(100447);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-13 11:20:27 +0100 (Wed, 13 Jan 2010)");
 script_bugtraq_id(37714);
 script_cve_id("CVE-2009-4490","CVE-2009-4491");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Acme thttpd and mini_httpd Terminal Escape Sequence in Logs Command Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37714");
 script_xref(name : "URL" , value : "http://www.acme.com/software/mini_httpd/");
 script_xref(name : "URL" , value : "http://www.acme.com/software/thttpd/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/508830");

 script_description(desc);
 script_summary("Determine the thttpd/mini_httpd version");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if("Server: mini_httpd/" >< banner) {
  version = eregmatch(pattern:"Server: mini_httpd/([0-9.]+)", string: banner);
  if(!isnull(version[1])) {
    if(version_is_less_equal(version: version[1], test_version: "1.19")) {
      security_warning(port:port);
      exit(0);
    }  
  }  
} 
else if("Server: thttpd/" >< banner) {
   version = eregmatch(pattern:"Server: thttpd/([0-9.]+[a-z]*)", string: banner);
   if(!isnull(version[1])) {
     if(version_is_less_equal(version: version[1], test_version: "2.25b")) {
       security_warning(port:port);
       exit(0);
     }  
   }  
}  

exit(0);
