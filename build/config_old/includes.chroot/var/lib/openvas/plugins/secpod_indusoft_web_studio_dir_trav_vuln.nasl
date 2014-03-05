###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_indusoft_web_studio_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# InduSoft Web Studio Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  via an invalid request.
  Impact Level: Application";
tag_affected = "InduSoft Web Studio version 6.1 and 7.x before 7.0+Patch 1";

tag_insight = "The flaw is due to an error in 'NTWebServer', which allows remote
  attackers to execute arbitrary code via an invalid request.";
tag_solution = "Install the hotfix from below link
  http://www.indusoft.com/hotfixes/hotfixes.php";
tag_summary = "This host is installed with Indusoft Web Studio and is prone to
  directory traversal vulnerability.";

if(description)
{
  script_id(902371);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-1900");
  script_bugtraq_id(47842);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_name("InduSoft Web Studio Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/73413");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42883");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/67419");
  script_xref(name : "URL" , value : "http://www.indusoft.com/hotfixes/hotfixes.php");

  script_description(desc);
  script_summary("Check for the version of Indusoft Web Studio");
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

## Variable Initialization
key = "";
item = "";
indName = "";
indVer = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ## Check for InduSoft Web Studio DisplayName
  indName = registry_get_sz(key:key + item, item:"DisplayName");
  if("InduSoft Web Studio" >< indName)
  {
    indVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!indVer){
      exit(0);
    }

    indVer = eregmatch(string:indVer, pattern:"([0-9.]+)");
    if(indVer[1])
    {
      ## Check for version
      if(version_is_equal(version:indVer[1], test_version:"6.1") ||
         version_is_equal(version:indVer[1], test_version:"7.0"))
      {
        security_hole(0);
        exit(0);
      }
    }
  }
}
