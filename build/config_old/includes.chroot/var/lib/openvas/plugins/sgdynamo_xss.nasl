# OpenVAS Vulnerability Test
# $Id: sgdynamo_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: sgdynamo_xss
#
# Authors:
# Scott Shebby (12/2003) 
# changes by rd:
# - Description
# - Support for multiple HTTP directories
# - HTTP Keepalive support
#
# Copyright:
# Copyright (C) 2003 Scott Shebby
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
tag_summary = "The remote host is running the CGI 'sgdynamo.exe'. 

There is a bug in some versions of this CGI which makes it vulnerable to
a cross site scripting attack.";

tag_solution = "None at this time";

if(description)
{
 script_id(11955);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4720);
 script_cve_id("CVE-2002-0375");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "sgdynamo_xss";
 script_name(name);
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "sgdynamo.exe XSS Vulnerability";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Scott Shebby");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 url = dir + "/sgdynamo.exe?HTNAME=<script>foo</script>";
 req = http_get(item:url, port:port);
 resp = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( resp == NULL ) exit(0);
 if ( "<script>foo</script>" >< res )
 {
   security_warning(port);
   exit(0);
 }
}