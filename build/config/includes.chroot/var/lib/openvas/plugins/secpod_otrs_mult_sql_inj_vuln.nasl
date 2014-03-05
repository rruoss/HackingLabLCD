##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_otrs_mult_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Open Ticket Request System (OTRS) Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902016";
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 14 $");
  script_cve_id("CVE-2010-0438");
  script_bugtraq_id(38146);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_name("Open Ticket Request System (OTRS) Multiple SQL Injection Vulnerabilities");

tag_summary =
"This host is running Open Ticket Request System (OTRS) and is prone to
multiple SQL injection vulnerabilities.";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"The flaws are due to error in 'Kernel/System/Ticket.pm' in 'OTRS-Core'. It
fails to sufficiently sanitize user-supplied data before using it in SQL queries.";

tag_impact =
"Successful exploitation will allow attackers to manipulate SQL queries to
read or modify records in the database, could also allow access to more
administrator permissions.

Impact Level: Application";

tag_affected =
"Open Ticket Request System (OTRS) version prior to 2.1.9, 2.2.9,2.3.5 and 2.4.7";

tag_solution =
"Upgarde to Open Ticket Request System (OTRS) 2.1.9, 2.2.9, 2.3.5, 2.4.7
For updates refer to http://otrs.org/download/";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://otrs.org/advisory/OSA-2010-01-en/");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2010-0438");
  script_summary("Check for the version of Open Ticket Request System (OTRS)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyrightopyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialisation
port = "";
vers = "";

## Get Application HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))
{
  if(version_in_range(version:otrsVer[1], test_version:"2.1.0", test_version2:"2.1.8") ||
     version_in_range(version:otrsVer[1], test_version:"2.2.0", test_version2:"2.2.8") ||
     version_in_range(version:otrsVer[1], test_version:"2.3.0", test_version2:"2.3.4") ||
     version_in_range(version:otrsVer[1], test_version:"2.4.0", test_version2:"2.4.6"))
   {
     security_hole(port);
   }
}
