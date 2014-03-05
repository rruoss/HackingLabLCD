###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-002.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Windows Object Packager Remote Code Execution Vulnerability (2603381)
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code with
  the privileges of the user running the affected application. Failed exploit
  attempts will result in a denial-of-service condition.
  Impact Level: System";
tag_affected = "Windows Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.";
tag_insight = "The flaw is due to the way that Windows registers and uses Windows
  Object Packager. This can be exploited to load an executable file
  (packager.exe) in an insecure manner by tricking a user into opening a
  Publisher file '.pub' containing an embedded packaged object located on a
  remote WebDAV or SMB share.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-002";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-002.";

if(description)
{
  script_id(902784);
  script_version("$Revision: 12 $");
  script_bugtraq_id(51297);
  script_cve_id("CVE-2012-0009");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-11 10:54:36 +0530 (Wed, 11 Jan 2012)");
  script_name("Microsoft Windows Object Packager Remote Code Execution Vulnerability (2603381)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45189/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026494");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-002");

  script_description(desc);
  script_summary("Check for the hotfix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("secpod_reg.inc");

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

## MS12-002 Hotfix 2603381
## File information is not available
## Checking for hotfix only
if(hotfix_missing(name:"2603381") == 1){
  security_hole(0);
}
