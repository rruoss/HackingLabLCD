###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_acdsee_fotoslate_mult_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# ACDSee FotoSlate Multiple Buffer Overflow Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application.
  Impact Level: System/Application";
tag_affected = "ACDSee Fotoslate version 4.0 Build 146";

tag_insight = "The flaws are due to boundary error when processing the 'id' parameter
  of a '<String>' or '<Int>' tag in a FotoSlate Project (PLP) file. This can be
  exploited to cause a stack-based buffer overflow via an overly long string
  assigned to the parameter.";
tag_solution = "No solution or patch is available as of 23rd September 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://store.acdsee.com/store/acd/DisplayProductDetailsPage/productID.69650700/Locale.en_US/Currency.USD?resid=TnsbEQoHArEAAG62J0EAAAAt&rests=1316765102137";
tag_summary = "This host is installed with ACDSee FotoSlate and is prone to
  multiple buffer overflow vulnerabilities.";

if(description)
{
  script_id(902732);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_cve_id("CVE-2011-2595");
  script_bugtraq_id(49558);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("ACDSee FotoSlate PLP Multiple Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/75425");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44722");

  script_description(desc);
  script_summary("Check for the version of ACDSee Fotoslate");
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

## Check FotoSlate is installed
if(!registry_key_exists(key:"SOFTWARE\ACD Systems\FotoSlate")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ## Check for FotoSlate DisplayName
  fotoName = registry_get_sz(key:key + item, item:"DisplayName");
  if("FotoSlate" >< fotoName)
  {
    ## Check for FotoSlate DisplayVersion
    fotoVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!fotoVer){
      exit(0);
    }

    ## Check for FotoSlate version equals to 4.0 Build 146 => '4.0.146'
    if(version_is_equal(version:fotoVer, test_version:"4.0.146"))
    {
        security_hole(0) ;
        exit(0);
    }
  }
}
