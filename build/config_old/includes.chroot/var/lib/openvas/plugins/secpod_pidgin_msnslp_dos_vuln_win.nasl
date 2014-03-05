###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pidgin_msnslp_dos_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Pidgin MSN SLP Packets Denial Of Service Vulnerability (Win)
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
tag_impact = "Attackers can exploit this issue to execute arbitrary code, corrupt memory
  and cause the application to crash.
  Impact Level: Application";
tag_affected = "Pidgin version prior to 2.5.9 on Windows.";
tag_insight = "An error in the 'msn_slplink_process_msg()' function while processing
  malformed MSN SLP packets which can be exploited to overwrite of an
  arbitrary memory location.";
tag_solution = "Upgrade to Pidgin version 2.5.9
  http://pidgin.im/download";
tag_summary = "This host has Pidgin installed and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(900919);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2694");
  script_bugtraq_id(36071);
  script_name("Pidgin MSN SLP Packets Denial Of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36384");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=34");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2303");

  script_description(desc);
  script_summary("Check for the Version of Pidgin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_require_keys("Pidgin/Win/Ver");
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

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer != NULL)
{
  if(version_is_less(version:pidginVer, test_version:"2.5.9")){
    security_hole(0);
  }
}
