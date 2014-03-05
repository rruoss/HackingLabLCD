###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_mxit_msg_parsing_bof_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Pidgin MXit Message Parsing Buffer Overflow Vulnerability (Windows)
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
tag_impact = "Successful exploitation will allow attacker to cause a stack-based buffer
  overflow via a specially crafted RX message which may lead to the execution
  of arbitrary code in the context of the application or to denial-of-service.
  Impact Level: System/Application";
tag_affected = "Pidgin version prior to 2.10.5 on Windows";
tag_insight = "A boundary error within the 'mxit_show_message()' function, when parsing
  incoming instant messages containing inline images.";
tag_solution = "Upgrade to Pidgin version 2.10.5 or later,
  For updates refer to http://pidgin.im/download";
tag_summary = "This host has installed with Pidgin and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(803102);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-3374");
  script_bugtraq_id(54322);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-19 13:10:50 +0530 (Fri, 19 Oct 2012)");
  script_name("Pidgin MXit Message Parsing Buffer Overflow Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49831/");
  script_xref(name : "URL" , value : "http://www.osvdb.org/show/osvdb/83605");
  script_xref(name : "URL" , value : "http://hg.pidgin.im/pidgin/main/rev/ded93865ef42");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/index.php?id=64");

  script_description(desc);
  script_summary("Check if pidgin version less than 2.10.5 on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
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

## Variable initialization
pidginVer = "";

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer)
{
  if(version_is_less(version:pidginVer, test_version:"2.10.5")){
    security_hole(0);
  }
}
