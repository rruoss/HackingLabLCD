###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apc_powerchute_business_edtn_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# APC PowerChute Business Edition Unspecified Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of an affected site.
  Impact Level: Application.";
tag_affected = "APC PowerChute Business Edition version prior to 8.5";

tag_insight = "The flaw exists due to improper validation of certain unspecified input
  before being returned to the user.";
tag_solution = "Upgrade to the APC PowerChute Business Edition version 8.5 or later
  For updates refer to http://www.apc.com/products/family/index.cfm?id=125&ISOCountryCode=us";
tag_summary = "This host is running APC PowerChute Business Edition and is prone
  to cross site scripting vulnerability.";

if(description)
{
  script_id(902771);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4263");
  script_bugtraq_id(51022);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"creation_date", value:"2011-12-16 13:03:34 +0530 (Fri, 16 Dec 2011)");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_name("APC PowerChute Business Edition Unspecified Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47113/");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN61695284/index.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000100.html");

  script_description(desc);
  script_summary("Check for the version of APC PowerChute Business Edition");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
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

## Check if the server is installed
if(!registry_key_exists(key:"SOFTWARE\APC\PowerChute Business Edition\server")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  powerName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check for DisplayName
  if("PowerChute Business Edition Console" >< powerName)
  {
    ## Get the version
    powerVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(powerVer)
    {
      ## Check for version
      if(version_is_less(version:powerVer, test_version:"8.5.0"))
      {
        security_warning(0) ;
        exit(0);
      }
    }
  }
}
