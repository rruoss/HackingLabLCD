###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ucs_62851.nasl 11 2013-10-27 10:12:02Z jan $
#
# Cisco Unified Computing System Multiple Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103805";
CPE = "cpe:/a:cisco:unified_computing_system_software";

tag_insight = "This issue is being tracked by Cisco bug IDs:
CSCtc91207
CSCtd32371
CSCtg48206
CSCtq86543
CSCts53746";

tag_impact = "CSCtc91207:
An attacker can exploit this issue to bypass the authentication mechanism
and impersonate other users of the system. This may lead to further
attacks.

CSCtd32371:
Attackers can exploit this issue to execute arbitrary code within the
context of the affected application. Failed exploit attempts will result in
denial-of-service conditions. 

CSCtg48206:
Attackers can exploit this issue to cause the service to stop responding
resulting in denial-of-service conditions. 

CSCtq86543:
Successful exploits will allow attackers to obtain sensitive information.
This may result in the complete compromise of the system.

CSCts53746:
An attacker can exploit this issue to bypass the authentication mechanism
and gain access to the IP KVM console of the physical or virtual device.
This may lead to further attacks.";

tag_affected = "Cisco Unified Computing System 1.0(x)
1.1(x)
1.2(x)
1.3(x)
1.4(x)
2.0(1x) and Prior";

tag_summary = "Cisco Unified Computing System is prone to multiple
vulnerabillities";

tag_solution = "Update to 2.1.1e";
tag_vuldetect = "Check the Cisco Unified Computing System Version";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(59451,59453,59457,59459,59455);
 script_cve_id("CVE-2013-1182","CVE-2013-1183","CVE-2013-1184","CVE-2013-1185","CVE-2013-1186");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 11 $");

 script_name("Cisco Unified Computing System Multiple Vulnerabilities");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59451");
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59453");
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59457");
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59459");
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59455");

 script_xref(name:"URL", value:"http://www.cisco.com/");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-10 19:10:32 +0200 (Thu, 10 Oct 2013)");
 script_description(desc);
 script_summary("Check the installed version.");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_cisco_ucs_manager_detect.nasl");
 script_require_ports("Services/www", 443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("cisco_ucs_manager/installed");

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

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port);
if(!version)exit(0);

vers = eregmatch(pattern:"^([0-9.]+)\(([^)]+)\)", string:version);
if(isnull(vers[1]) || isnull(vers[2]))exit(0);

major = vers[1];
build = vers[2];

vuln = FALSE;

# cisco recommended to update to 2.1.1e. So we check for < 2.1.1e. Example
# Version: 2.0(1s)
if(version_is_less(version:major, test_version:"2.1")) vuln = TRUE;
if(version_is_equal(version:major, test_version:"2.1")) {
  if(build =~ "^(0[^0-9]|1[a-d])") vuln = TRUE;
}

if(vuln) {
  security_hole(port:port);
  exit(0);
}  

exit(99);
