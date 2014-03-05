###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_clamav_dos_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# ClamAV Denial of Service Vulnerability (Win)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Attackers can exploit this issue by executing arbitrary code via a crafted
  URL in the context of affected application, and can cause denial of service.
  Impact Level: Application";
tag_affected = "ClamAV before 0.95.1 on Windows.";
tag_insight = "- Error in CLI_ISCONTAINED macro in libclamav/others.h while processing
    malformed files packed with UPack.
  - Buffer overflow error in cli_url_canon() function in libclamav/phishcheck.c
    while handling specially crafted URLs.";
tag_solution = "Upgrade to ClamAV 0.95.1
  http://www.clamav.net/download";
tag_summary = "The host is installed with ClamAV and is prone to Denial of Service
  Vulnerability.";

if(description)
{
  script_id(900546);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1371", "CVE-2009-1372");
  script_bugtraq_id(34446);
  script_name("ClamAV Denial of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34612/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0985");

  script_description(desc);
  script_summary("Check for the Version of ClamAV");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_detect_win.nasl");
  script_require_keys("ClamAV/Win/Ver");
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

avVer = get_kb_item("ClamAV/Win/Ver");
if(avVer == NULL){
  exit(0);
}

if(version_is_less(version:avVer, test_version:"0.95.1")){
  security_hole(0);
}
