###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ros_62798.nasl 11 2013-10-27 10:12:02Z jan $
#
# RuggedCom Rugged Operating System Remote Security Bypass Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103803";
CPE = "cpe:/o:ruggedcom:ros";

tag_insight = "The security issue is caused due to an error when handling
alarms configuration within the web user interface, which can be exploited
by guest and operator users to manipulate otherwise inaccessible
alarm configuration settings.";

tag_impact = "An attacker may exploit this issue to bypass certain security
restrictions and perform unauthorized actions.";

tag_affected = "Rugged Operating System prior to 3.12.2 are vulnerable.";

tag_summary = "Rugged Operating System is prone to a security-bypass vulnerability.";

tag_solution = "Updates are available. Please see the references or vendor advisory
for more information.";

tag_vuldetect = "Check the Rugged Operating System version.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(62798);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

 script_name("RuggedCom Rugged Operating System Remote Security Bypass Vulnerability");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62798");
 script_xref(name:"URL", value:"http://www.ruggedcom.com/");
 
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-10 17:14:09 +0200 (Thu, 10 Oct 2013)");
 script_description(desc);
 script_summary("Check the Rugged Operating System version");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_ros_detect.nasl");
 script_require_ports("Services/www", 80, "Services/telnet", 23);
 script_require_keys("rugged_os/installed");

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

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID))exit(0);

if(version_is_less(version:vers, test_version:"3.12.2")) {
    security_hole(port:0);
    exit(0);
}  

exit(99);

