###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_http_file_server_39544.nasl 14 2013-10-27 12:33:37Z jan $
#
# HTTP File Server Security Bypass and Denial of Service Vulnerabilities
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
tag_summary = "HTTP File Server is prone to multiple vulnerabilities including a security-
bypass issue and a denial-of-service issue.

Exploiting these issues will allow an attacker to download files from
restricted directories within the context of the application or cause
denial-of-service conditions.";

tag_solution = "Reportedly the vendor has fixed the issue. Please see the references
for more information.";

if (description)
{
 script_id(100585);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)");
 script_bugtraq_id(39544);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("HTTP File Server Security Bypass and Denial of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39544");
 script_xref(name : "URL" , value : "http://www.rejetto.com/hfs/?f=intro");
 script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/hfsref-adv.txt");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if HTTP File Server is prone to multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
if("Server: HFS" >!< banner)exit(0);

version = eregmatch(pattern:"Server: HFS ([0-9.]+)([a-z]*)", string:banner);
if(isnull(version[1]))exit(0);

if(version[1] == "2.2") {
  if(version[2] =~ "^[a-e]" || version[2] == NULL) {
    security_warning(port:port);
    exit(0);
  }  
}  

exit(0);

