##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_vm_virtualbox_unspecified_vuln_feb13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Oracle VM VirtualBox Unspecified Vulnerability - Feb13 (Windows)
#
# Authors:
# Arun kallavi <karun@secpod.com>
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
tag_solution = "Apply the patch from below link,
  http://www.oracle.com/technetwork/topics/security/cpujan2013-1515902.html

  *****
  NOTE: Ignore this warning, if above mentioned workaround is manually applied.
  *****";

tag_impact = "Successful exploitation allows malicious local users to perform certain
  actions with escalated privileges.
  Impact Level: Application";

tag_affected = "Oracle VM VirtualBox versions 4.0, 4.1 and 4.2 on Windows";
tag_insight = "The flaw is due to an unspecified error within the core component and can be
  exploited to cause a hang and manipulate certain VirtualBox accessible data.";
tag_summary = "This host is installed with Oracle VM VirtualBox and is prone to
  unspecified vulnerability.";

if(description)
{
  script_id(803300);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-0420");
  script_bugtraq_id(57383);
  script_tag(name:"cvss_base", value:"2.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-01 11:01:15 +0530 (Fri, 01 Feb 2013)");
  script_name("Oracle VM VirtualBox Unspecified Vulnerability - Feb13 (Windows)");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://www.osvdb.org/89249");
  script_xref(name : "URL" , value : "http://www.scip.ch/en/?vuldb.7413");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51893");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujan2013-1515902.html");

  script_description(desc);
  script_summary("Check the vulnerable version of Oracle VM VirtualBox on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_require_keys("Oracle/VirtualBox/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


# Variable Initialization
vmVer = "";

# Check for product Oracle VM VirtuaBox
vmVer = get_kb_item("Oracle/VirtualBox/Win/Ver");

# Check for vulnerable version
if(vmVer && vmVer =~ "^4")
{
  if(vmVer == "4.0.0"|| vmVer == "4.1.0"|| vmVer == "4.2.0")
  {
    security_warning(0);
    exit(0);
  }
}
