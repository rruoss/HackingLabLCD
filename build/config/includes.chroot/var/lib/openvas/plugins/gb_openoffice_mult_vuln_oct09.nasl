###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openoffice_mult_vuln_oct09.nasl 15 2013-10-27 12:49:54Z jan $
#
# OpenOffice.org Multiple Vulnerabilities - Oct09 (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Attackers can exploit these issues to execute code within the context of
  the affected application and can deny the service.
  Impact Level: Application";
tag_affected = "OpenOffice.org version 3.1.1 and prior on Windows.";
tag_insight = "OpenOffice is prone to multiple unspecified remote security vulnerabilities,
  including a stack-based overflow issue and two other unspecified issues.";
tag_solution = "No solution or patch is available as of 08th October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.openoffice.org/";
tag_summary = "The host has OpenOffice.org installed and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801114);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3569", "CVE-2009-3570", "CVE-2009-3571");
  script_bugtraq_id(36285);
  script_name("OpenOffice.org Multiple Vulnerabilities - Oct09 (Win)");
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
  script_xref(name : "URL" , value : "http://intevydis.com/vd-list.shtml");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Sep/1022832.html");

  script_description(desc);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_summary("Check for the version of OpenOffice.org");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_require_keys("OpenOffice/Win/Ver");
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

openVer = get_kb_item("OpenOffice/Win/Ver");
if(!openVer){
  exit(0);
}

# Check for OpenOffice version 3.1.1 => (3.1.9420)
if(version_is_less_equal(version:openVer, test_version:"3.1.9420")){
  security_hole(0);
}
