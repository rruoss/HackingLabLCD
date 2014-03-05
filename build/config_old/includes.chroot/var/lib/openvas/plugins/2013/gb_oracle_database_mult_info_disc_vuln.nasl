###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_database_mult_info_disc_vuln.nasl 66 2013-11-15 15:53:31Z veerendragg $
#
# Oracle Database Server Multiple Information Disclosure Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803956";
CPE = 'cpe:/a:oracle:database_server';

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 66 $");
  script_cve_id("CVE-2013-3826", "CVE-2013-5771");
  script_bugtraq_id(63046, 63044);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-11-15 16:53:31 +0100 (Fri, 15 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-10-28 14:27:36 +0530 (Mon, 28 Oct 2013)");
  script_name("Oracle Database Server Multiple Information Disclosure Vulnerabilities");

  tag_summary =
"This host is installed with Oracle Database Server and is prone to multiple
information disclosure vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of tnslsnr service and check it is
vulnerable or not.";

  tag_insight =
"Multiple flaws exist in Core RDBMS component and XML Parser component, no
further information available at this moment.";

  tag_impact =
"Successful exploitation will allow attackers to obtain potentially sensitive
information and manipulate certain data.

Impact Level: Application";

  tag_affected =
"Oracle Database Server version 11.1.0.7, 11.2.0.2, 11.2.0.3, and 12.1.0.1
are affected";

  tag_solution =
"Apply patches from below links,
http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html#AppendixDB
http://www.oracle.com/technetwork/topics/security/cpuoct2013verbose-1899842.html#DB

*****
NOTE: Ignore this warning if above mentioned patch is installed.
*****";

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
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/98515");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/55322");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuoct2013verbose-1899842.html#DB");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html#AppendixDB");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check for the vulnerable version of Oracle Database Server");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

if(report_paranoia < 2){
  exit(0);
}

## Variable initialisation
port = "";
ver = "";

## Get Oracle Database Server Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Get Version
if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(ver =~ "^(11\.[1|2]\.0|12\.1\.0)")
{
  if(version_in_range(version:ver, test_version:"11.2.0.2", test_version2:"11.2.0.3") ||
     version_is_equal(version:ver, test_version:"12.1.0.1") ||
     version_is_equal(version:ver, test_version:"11.1.0.7"))
  {
    security_hole(port);
  }
}
