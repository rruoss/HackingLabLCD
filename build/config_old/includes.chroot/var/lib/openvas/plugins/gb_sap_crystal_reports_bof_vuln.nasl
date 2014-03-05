###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_crystal_reports_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SAP Crystal Reports Print ActiveX Control Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  in the context of the application using the ActiveX control. Failed exploit
  attempts will likely result in denial-of-service condition.
  Impact Level: Application.";
tag_affected = "Crystal Reports 2008 SP3 Fix Pack 3.2(12.3.2.753)";

tag_insight = "The flaw exists due to boundary error in the 'CrystalReports12.CrystalPrintControl.1'
  ActiveX control (PrintControl.dll) when processing 'ServerResourceVersion'
  which can be exploited to cause a heap-based buffer overflow via an overly
  long string.";
tag_solution = "No solution or patch is available as of 5th April, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.sap.com/solutions/sapbusinessobjects/sme/freetrials/index.epx";
tag_summary = "This host is installed with SAP Crystal Reports and is prone to
  heap-based buffer overflow vulnerability.";

if(description)
{
  script_id(801767);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2010-2590");
  script_bugtraq_id(45387);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("SAP Crystal Reports Print ActiveX Control Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42305");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1024915");

  script_description(desc);
  script_summary("Check for the version of SAP Crystal Reports");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ## Confirm Application with name SAP
  sapName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Crystal Reports 2008" >< sapName)
  {
    ## Grep for version
    sapVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(sapVer != NULL)
    {
      ## Check for SAP Crystal Reports version equal to 12.3.2.753
      if(version_is_equal(version:sapVer, test_version:"12.3.2.753")){
        security_hole(0) ;
      }
    }
  }
}
