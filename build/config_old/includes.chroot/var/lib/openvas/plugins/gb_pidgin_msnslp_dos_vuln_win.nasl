###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_msnslp_dos_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Pidgin MSN Protocol Plugin Denial Of Service Vulnerability (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Attackers can exploit this issue to cause a denial of service (memory corruption)
  or possibly have unspecified other impact via unknown vectors.
  Impact Level: Application";
tag_affected = "Pidgin version prior to 2.6.4 on Windows.";
tag_insight = "This issue is due to an error in 'slp.c' within the 'MSN protocol plugin'
  in 'libpurple' when processing MSN request.";
tag_solution = "Upgrade to Pidgin version 2.6.6 or later.
  For updates refer to  http://pidgin.im/download";
tag_summary = "This host has Pidgin installed and is prone to Denial Of Service
  vulnerability";

if(description)
{
  script_id(800423);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-0277");
  script_name("Pidgin MSN Protocol Plugin Denial Of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/01/07/2");
  script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=2010-0277");

  script_description(desc);
  script_summary("Check for the version of Pidgin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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
  if(version_is_less_equal(version:pidginVer, test_version:"2.6.4")){
    security_warning(0);
  }
}
