###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zoom_telephonics_61044.nasl 11 2013-10-27 10:12:02Z jan $
#
# Multiple Zoom Telephonics Devices Multiple Security Vulnerabilities
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
tag_impact = "Exploiting these issues could allow an attacker to gain unauthorized
access and perform arbitrary actions, obtain sensitive information,
compromise the application, access or modify data, or exploit latent
vulnerabilities in the underlying database.
Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103756";

tag_insight = "When UPnP services and WAN http administrative access are enabled,
authorization and credential challenges can be bypassed by directly
accessing root privileged abilities via a web browser URL.
             
All aspects of the modem/router can be changed, altered and controlled
by an attacker, including gaining access to and changing the PPPoe/PPP
ISP credentials.";


tag_affected = "
X4 ADSL Modem and Router
X5 ADSL Modem and 4-port Router ";

tag_summary = "Multiple Zoom Telephonics devices are prone to an information-
disclosure vulnerability, an authentication bypass vulnerability and
an SQL-injection vulnerability.";

tag_solution = "Ask the Vendor for an update.";

tag_vuldetect = "Request /hag/pages/toolbox.htm and check if it is accessible without authentication.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(61044);
 script_cve_id("CVE-2013-5621", "CVE-2013-5625", "CVE-2013-5630");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
 script_version ("$Revision: 11 $");

 script_name("Multiple Zoom Telephonics Devices Multiple Security Vulnerabilities");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61044");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-12 15:24:34 +0200 (Mon, 12 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to access /hag/pages/toolbox.htm");
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
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("401 Unauthorized" >!< banner || "Server: Nucleus/" >!< banner)exit(0);

if(http_vuln_check(port:port, url:'/hag/pages/toolbox.htm',pattern:"<title>Advanced Setup", extra_check:make_list("WAN Configuration","ADSL Status"))) {
     
  security_hole(port:port);
  exit(0);

}

exit(0);

