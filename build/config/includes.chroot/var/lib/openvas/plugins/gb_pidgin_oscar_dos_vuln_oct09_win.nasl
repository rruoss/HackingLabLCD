###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_oscar_dos_vuln_oct09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Pidgin Oscar Protocol Denial of Service Vulnerability (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to cause a Denial of Service.
  Impact Level: Application";
tag_affected = "Pidgin version prior to 2.6.3 on Windows.";
tag_insight = "This issue is caused by an error in the Oscar protocol plugin when processing
  malformed ICQ or AIM contacts sent by the SIM IM client, which could cause an
  invalid memory access leading to a crash.";
tag_solution = "Upgrade to Pidgin version 2.6.3
  http://pidgin.im/download";
tag_summary = "This host has Pidgin installed and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(801030);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3615");
  script_bugtraq_id(36719);
  script_name("Pidgin Oscar Protocol Denial of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37072");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53807");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=41");
  script_xref(name : "URL" , value : "http://developer.pidgin.im/wiki/ChangeLog");

  script_description(desc);
  script_summary("Check for the version of Pidgin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
  if(version_is_less(version:pidginVer, test_version:"2.6.3")){
    security_warning(0);
  }
}
