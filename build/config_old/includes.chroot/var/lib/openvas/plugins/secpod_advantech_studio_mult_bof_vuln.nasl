###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_advantech_studio_mult_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Advantech Studio Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code.
  Impact Level: Application.";
tag_affected = "Advantech Advantech Studio 6.1 SP6 Build 61.6.0";

tag_insight = "The flaw exists due to a buffer overflow error in the ISSymbol ActiveX
  control (ISSymbol.ocx) when processing an overly long 'InternationalOrder',
  'InternationalSeparator', 'bstrFileName' or 'LogFileName' property, which
  could be exploited by attackers to execute arbitrary code by tricking a user
  into visiting a specially crafted web page.";
tag_solution = "No solution or patch is available as of 20th May, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://support.advantech.com.tw/support/DownloadSearchByProduct.aspx?keyword=Advantech+Studio";
tag_summary = "This host is installed with Advantech Studio and is prone multiple
  to buffer overflow vulnerability.";

if(description)
{
  script_id(902370);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_cve_id("CVE-2011-0340");
  script_bugtraq_id(47596);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Advantech Studio Multiple Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42928");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2011-37/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/1116");

  script_description(desc);
  script_summary("Check for the version of ISSymbol.ocx");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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
  ## Check for InduSoft Thin Client DisplayName
  advName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Advantech Studio" >< advName)
  {
    ## Get the installed location
    advPath = registry_get_sz(key:key + item, item:"InstallLocation");
    ocxPath = advPath + "\Redist\Wince 4.0\armv4t\ISSymbolCE.ocx";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ocxPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ocxPath);

    ocxVer = GetVer(file:file, share:share);
    if(!isnull(ocxVer))
    {
      if(version_is_equal(version:ocxVer, test_version:"301.1009.2904.0") ||
         version_is_equal(version:ocxVer, test_version:"61.6.0.0")){
        security_hole(0);
      }
    }
  }
}
