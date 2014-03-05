###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_d_link_dsl_multiple_vulnerabilities_05_2013.nasl 11 2013-10-27 10:12:02Z jan $
#
# D-Link DSL-320B Multiple Security Vulnerabilities
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
tag_summary = "D-Link DSL-320B is prone to the following security
vulnerabilities:

1. Access to the Config file without authentication 
2. Access to the logfile without authentication
3. Stored XSS within parental contro

An attacker can exploit these issues to gain access to potentially
sensitive information, decrypt stored passwords, steal cookie-based
authentication credentials.";


tag_solution = "Firmware update is available.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103706";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");

 script_name("D-Link DSL-320B Multiple Security Vulnerabilities");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name:"URL", value:"http://www.s3cur1ty.de/m1adv2013-018");
 script_xref(name:"URL", value:"http://www.dlink.com/de/de/home-solutions/connect/modems-and-gateways/dsl-320b-adsl-2-ethernet-modem");
 script_xref(name:"URL", value:"http://www.dlink.com/");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-05-06 12:58:41 +0200 (Mon, 06 May 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to download /config.bin");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(banner && "Server: micro_httpd" >!< banner)exit(0);

if(http_vuln_check(port:port, url:"/",pattern:"DSL-")) {

  if(http_vuln_check(port:port, url:"/config.bin",pattern:"sysPassword",extra_check:"sysUserName")) {
    security_hole(port:port);
    exit(0);
  }  

  exit(99);
     
}

exit(0);

