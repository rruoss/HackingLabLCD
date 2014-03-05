###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_heap_based_bof_vuln_macosx.nasl 11 2013-10-27 10:12:02Z jan $
#
# RealNetworks RealPlayer Heap Based BoF Vulnerability (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
tag_impact = "Successful exploitation allows remote attackers to to cause heap
  based buffer overflow leading to arbitrary code execution or denial of
  service condition.
  Impact Level: System/Application";

tag_affected = "RealPlayer version 12.0.0.1701 and prior on Mac OS X";
tag_insight = "Flaw due to improper sanitization of user-supplied input when parsing MP4
  files.";
tag_solution = "Upgrade to RealPlayer version 12.0.1.1738 or later,
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to heap
  based buffer overflow vulnerability.";

if(description)
{
  script_id(803602);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1750");
  script_bugtraq_id(58539);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-14 18:45:01 +0530 (Tue, 14 May 2013)");
  script_name("RealNetworks RealPlayer Heap Based BoF Vulnerability (Mac OS X)");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/91438");
  script_xref(name : "URL" , value : "http://www.scip.ch/en/?vuldb.8026");
  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2013-1750");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/03152013_player/en");
  script_summary("Check for the vulnerable version of RealPlayer on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_realplayer_detect_macosx.nasl");
  script_mandatory_keys("RealPlayer/MacOSX/Version");
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

## Variable Initialization
rpVer = "";

## Get RealPlayer version from KB
rpVer = get_kb_item("RealPlayer/MacOSX/Version");
if(!rpVer){
  exit(0);
}

## Check for Realplayer version <= 12.0.0.1701
if(version_is_less_equal(version:rpVer, test_version:"12.0.0.1701"))
{
  security_hole(0);
  exit(0);
}
