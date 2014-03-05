###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_dec12_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adobe Flash Player Multiple Vulnerabilities - December12 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code or denial of service.
  Impact Level: System/Application";
tag_affected = "Adobe Flash Player version before 10.3.183.48, 11.x before 11.5.502.136 on Mac OS X";
tag_insight = "Multiple unspecified errors and integer overflow exists that could lead to
  code execution.";
tag_solution = "Update to Adobe Flash Player version 10.3.183.48 or 11.5.502.136 or later,
  For updates refer to http://get.adobe.com/flashplayer";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803075);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5676", "CVE-2012-5677", "CVE-2012-5678");
  script_bugtraq_id(56892, 56896, 56898);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-14 15:17:00 +0530 (Fri, 14 Dec 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities - December12 (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/88353");
  script_xref(name : "URL" , value : "http://osvdb.org/88354");
  script_xref(name : "URL" , value : "http://osvdb.org/88356");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51560");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027854");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2755801");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-27.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Player on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
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
playerVer = "";

# Check for Adobe Flash Player
playerVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(playerVer)
{
  # Grep for version less than 10.3.183.48 and 11.x less than 11.5.502.136
  if(version_is_less(version: playerVer, test_version:"10.3.183.48") ||
     version_in_range(version: playerVer, test_version:"11.0", test_version2:"11.5.502.135"))
  {
    security_hole(0);
    exit(0);
  }
}
