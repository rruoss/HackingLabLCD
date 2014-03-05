###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smc8024l2_54390.nasl 12 2013-10-27 11:15:33Z jan $
#
# SMC Networks SMC8024L2 Switch Web Interface Authentication Bypass Vulnerability
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
tag_summary = "The SMC Networks SMC8024L2 switch is prone to a remote authentication-
bypass vulnerability.

An attacker can exploit this issue to gain unauthorized administrative
access to all configuration pages to affected devices.";


if (description)
{
 script_id(103513);
 script_bugtraq_id(54390);
 script_cve_id("CVE-2012-2974");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("SMC Networks SMC8024L2 Switch Web Interface Authentication Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54390");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/377915");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-07-12 10:05:05 +0200 (Thu, 12 Jul 2012)");
 script_description(desc);
 script_summary("Determine if unauthorized access to a configuration page is possible.");
 script_category(ACT_GATHER_INFO);
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

url = string(dir, "/index.html");

if(http_vuln_check(port:port, url:url,pattern:"<title>SMC Networks Web Interface")) {

  url = '/status/status_ov.html';

  if(http_vuln_check(port:port, url:url,pattern:"<title>Status Overview",extra_check:make_list("macAddress","opVersion","systemName"))) {
     
    security_hole(port:port);
    exit(0);

  }  

}

exit(0);
