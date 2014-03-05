###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openjpeg_cmap_record_parsing_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# OpenJPEG CMAP Record Parsing Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  Impact Level: System/Application";
tag_affected = "OpenJPEG version prior to 1.5";

tag_insight = "The flaw is due to an error when parsing a CMAP record and can be
  exploited to cause an out of bounds write via specially crafted JPEG files.";
tag_solution = "Upgrade to the OpenJPEG version 1.5 or later,
  For updates refer to http://code.google.com/p/openjpeg/downloads/list";
tag_summary = "This host is installed with OpenJPEG and is prone to record parsing
  vulnerability.";

if(description)
{
  script_id(903019);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1499");
  script_bugtraq_id(52654);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-25 11:28:15 +0530 (Wed, 25 Apr 2012)");
  script_name("OpenJPEG CMAP Record Parsing Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48498/");
  script_xref(name : "URL" , value : "http://openjpeg.googlecode.com/svn/branches/openjpeg-1.5/NEWS");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/msvr/msvr12-004#section1");

  script_description(desc);
  script_summary("Check for the version of OpenJPEG");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\openjpeg";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for OpenJPEG DisplayName
openName = registry_get_sz(key:key, item:"DisplayName");
if("OpenJPEG" >< openName)
{
  ## Get the version from registry
  openVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(!openVer){
    exit(0);
  }

  ## Check for OpenJPEG version less than 1.5
  if(version_is_less(version:openVer, test_version:"1.5")){
    security_hole(0) ;
  }
}
