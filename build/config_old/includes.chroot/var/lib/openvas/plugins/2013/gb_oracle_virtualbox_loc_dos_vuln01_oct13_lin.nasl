###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_loc_dos_vuln01_oct13_lin.nasl 33 2013-10-31 15:16:09Z veerendragg $
#
# Oracle VM VirtualBox Local Denial of Service Vulnerability-01 Oct2013 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:oracle:vm_virtualbox";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804123";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 33 $");
  script_cve_id("CVE-2013-3792");
  script_bugtraq_id(60794);
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-31 16:16:09 +0100 (Do, 31. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-28 09:51:57 +0530 (Mon, 28 Oct 2013)");
  script_name("Oracle VM VirtualBox Local Denial of Service Vulnerability-01 Oct2013 (Linux)");

  tag_summary =
"This host is installed with Oracle VM VirtualBox and is prone to
unspecified vulnerability.";

  tag_vuldetect =
"Get the installed version of Oracle VM VirtualBox and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to unspecified errors related to 'core' component";

  tag_impact =
"Successful exploitation will allow local users to affect availability
and cause local denial of service.

Impact Level: Application";

  tag_affected =
"Oracle VM VirtualBox version 3.2.18 and before, 4.0.20 and before,4.1.28
and before,4.2.18 and before on Linux";

  tag_solution =
"Apply the patch from below link,
http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
      script_tag(name : "summary" , value : tag_summary);
      script_tag(name : "vuldetect" , value : tag_vuldetect);
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "insight" , value : tag_insight);
      script_tag(name : "affected" , value : tag_affected);
      script_tag(name : "impact" , value : tag_impact);
   }

  script_description(desc);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53858");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/60794");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");
  script_summary("Check for the vulnerable version of Oracle VM VirtualBox on Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
virVer = "";

## Get version
if(!virVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  CPE="cpe:/a:sun:virtualbox";
  if(!virVer=get_app_version(cpe:CPE, nvt:SCRIPT_OID))
    exit(0);
}

if(virVer)
{
  ## Check for vulnerable version
  if(version_in_range(version:virVer, test_version:"3.2.0", test_version2:"3.2.17")||
     version_in_range(version:virVer, test_version:"4.0.0", test_version2:"4.0.19")||
     version_in_range(version:virVer, test_version:"4.1.0", test_version2:"4.1.27")||
     version_in_range(version:virVer, test_version:"4.2.0", test_version2:"4.2.17"))
  {
    security_warning(0);
  }
}


