###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_web_server_41389.nasl 14 2013-10-27 12:33:37Z jan $
#
# Sun Java System Web Server Admin Interface Denial of Service Vulnerability
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
tag_summary = "Sun Java System Web Server is prone to a denial-of-service
vulnerability.

An attacker can exploit this issue to crash the effected application,
denying service to legitimate users.

Sun Java System Web Server 7.0 Update 7 is affected; other versions
may also be vulnerable.";


if (description)
{
 script_id(100703);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-07 12:47:04 +0200 (Wed, 07 Jul 2010)");
 script_bugtraq_id(41389);

 script_name("Sun Java System Web Server Admin Interface Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41389");
 script_xref(name : "URL" , value : "http://www.sun.com/software/products/web_srvr/home_web_srvr.xml");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Sun Java System Web Server version is 7.0 Update 7");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_sun_java_sys_web_serv_detect.nasl");
 script_require_ports("Services/www", 8989);
 script_require_keys("Sun/Java/SysWebServ/Ver","Sun/JavaSysWebServ/Port");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

if( get_kb_item("Sun/JavaSysWebServ/Ver") != "7.0"){
  exit(0);
}

port = get_http_port(default:8989);
if(!get_port_state(port))exit(0);

if(version = get_kb_item(string("Sun/JavaSysWebServ/",port,"/Ver"))) {

vers = str_replace(find:"U", string: version, replace:".");

  if(version_is_equal(version: vers, test_version: "7.0.7")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);
