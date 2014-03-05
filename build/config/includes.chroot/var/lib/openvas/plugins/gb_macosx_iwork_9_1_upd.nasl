###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_iwork_9_1_upd.nasl 13 2013-10-27 12:16:33Z jan $
#
# Apple Mac OS X iWork 9.1 Update
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
tag_impact = "Successful exploitation could allow attackers to opening a maliciously
  crafted files, which leads to an unexpected application termination or
  arbitrary code execution.
  Impact Level: System/Application";
tag_affected = "Mac OS X iwork version 9.0 through 9.0.5";
tag_insight = "The flaws are due to
  - a buffer overflow error, while handling the 'Excel' files.
  - a memory corruption issue, while handling the 'Excel' files and Microsoft
    Word documents.";
tag_solution = "Apply the update from below link
  For updates refer to http://support.apple.com/downloads/DL1097/en_US/iWork9.1Update.dmg";
tag_summary = "This host is missing an important security update according to
  Mac OS X iWork 9.1 Update.";

if(description)
{
  script_id(802146);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_cve_id("CVE-2010-3785", "CVE-2010-3786", "CVE-2011-1417");
  script_bugtraq_id(44812, 44799, 46832);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Apple Mac OS X iWork 9.1 Update");
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
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4684");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce//2011//Jul/msg00003.html");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Checks for Mac OS X iWork 9.1 Update");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_iwork_detect_macosx.nasl");
  script_require_ports("Apple/iWork/Keynote/MacOSX/Version");
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

iworkVer = get_kb_item("Apple/iWork/Keynote/MacOSX/Version");
if(!iworkVer){
  exit(0);
}

## Refer below wiki link for version mapping
## http://en.wikipedia.org/wiki/IWork
## After installing the update, keynote version will gets update
## Check for iWork keynote version
if(version_in_range(version:iworkVer, test_version:"5.0", test_version2:"5.0.5")){
  security_hole(0);
}
