###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_av_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Kaspersky AntiVirus Buffer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application or may cause privilege escalation.

  Impact level: Application/System";

tag_affected = "Kaspersky AntiVirus version 7.0.1.325 and prior on Windows.
  Kaspersky AntiVirus Workstation version 6.0.3.837 and prior on Windows.";
tag_insight = "This flaw is due to an error in the klim5.sys driver when handling Kernel
  API calls IOCTL 0x80052110 which can overwrite callback function pointers
  and execute arbitrary codes into the context of the application.";
tag_solution = "No solution or patch is available as of 16th February, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.kaspersky.com/productupdates?chapter=146274385";
tag_summary = "This host is running Kaspersky AntiVirus or Workstation and is
  prone to Buffer Overflow Vulnerability.";

if(description)
{
  script_id(800242);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-16 16:42:20 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(33561);
  script_cve_id("CVE-2009-0449");
  script_name("Kaspersky AntiVirus Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33788");
  script_xref(name : "URL" , value : "http://www.wintercore.com/advisories/advisory_W020209.html");

  script_description(desc);
  script_summary("Check for the version of Kaspersky AV/Workstation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_require_keys("Kaspersky/AV/Ver", "Kaspersky/AV-Workstation/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

kavVer = get_kb_item("Kaspersky/AV/Ver");
if(kavVer != NULL)
{
  if(version_is_less_equal(version:kavVer, test_version:"7.0.1.325")){
    security_hole(0);
    exit(0);
  }
}

kavwVer = get_kb_item("Kaspersky/AV-Workstation/Ver");
if(kavwVer != NULL)
{
  if(version_is_less_equal(version:kavwVer, test_version:"6.0.3.837")){
    security_hole(0);
  }
}
