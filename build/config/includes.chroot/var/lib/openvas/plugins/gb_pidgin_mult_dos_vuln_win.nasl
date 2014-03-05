###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_mult_dos_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Pidgin Multiple Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to crash the affected
  application, denying service to legitimate users.
  Impact Level: Application";
tag_affected = "Pidgin version prior to 2.10.2 on Windows";
tag_insight = "The flaws are due to
  - A NULL pointer dereference error within the 'get_iter_from_chatbuddy()'
    function when handling nickname changes in XMPP chat rooms.
  - An error within the 'msn_oim_report_to_user()' function when handling
    UTF-8 encoded message.";
tag_solution = "Upgrade to Pidgin version 2.10.2 or later,
  For updates refer to http://pidgin.im/download";
tag_summary = "This host is installed with Pidgin and is prone to multiple
  denial of service vulnerabilities.";

if(description)
{
  script_id(802713);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1178", "CVE-2011-4939");
  script_bugtraq_id(52475, 52476);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-19 17:45:29 +0530 (Mon, 19 Mar 2012)");
  script_name("Pidgin Multiple Denial of Service Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48303/");
  script_xref(name : "URL" , value : "http://pidgin.im/news/security/?id=61");
  script_xref(name : "URL" , value : "http://pidgin.im/news/security/?id=60");
  script_xref(name : "URL" , value : "http://developer.pidgin.im/ticket/14392");
  script_xref(name : "URL" , value : "http://developer.pidgin.im/ticket/14884");

  script_description(desc);
  script_summary("Check for the Version of Pidgin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

## Variable Initialization
pidginVer = "";

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer != NULL)
{
  if(version_is_less(version:pidginVer, test_version:"2.10.2")){
    security_hole(0);
  }
}
