###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-025.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft OneNote Information Disclosure Vulnerability (2816264)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to disclose sensitive
  information from the affected system.
  Impact Level: Application";

tag_affected = "Microsoft OneNote 2010 Service Pack 1";
tag_insight = "The flaws due to allocating memory when validating buffer sizes during
  the handling of a specially crafted OneNote (.ONE) file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-025";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-025.";

if(description)
{
  script_id(903304);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-0086");
  script_bugtraq_id(58387);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-13 09:39:46 +0530 (Wed, 13 Mar 2013)");
  script_name("Microsoft OneNote Information Disclosure Vulnerability (2816264)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.com/91153");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2760600");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-au/security/bulletin/ms13-025");

  script_description(desc);
  script_summary("Check for the vulnerable version OneNote in Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_onenote_detect.nasl");
  script_mandatory_keys("MS/Office/OneNote/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("version_func.inc");

# Variable Initialization
noteVer ="";

# Get the version from KB
noteVer = get_kb_item("MS/Office/OneNote/Ver");

# Check for Nuance PDF Editor Version
if(noteVer && version_in_range(version:noteVer, test_version:"14.0", test_version2:"14.0.6134.4999"))
{
  security_hole(0);
  exit(0);
}
