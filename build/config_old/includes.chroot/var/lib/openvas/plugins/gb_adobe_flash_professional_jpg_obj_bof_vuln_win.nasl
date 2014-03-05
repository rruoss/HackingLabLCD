###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_professional_jpg_obj_bof_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adobe Flash Professional JPG Object Processing BOF Vulnerability (Windows)
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code.
  Impact Level: Application/System";
tag_affected = "Adobe Flash Professional version CS5.5.1 (11.5.1.349) and prior on Windows";
tag_insight = "The flaw is due to an error in 'Flash.exe' when allocating memory to
  process a JPG object using its image dimensions.";
tag_solution = "Upgrade to Adobe Flash Professional version CS6 or later,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Professional and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(802781);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0778");
  script_bugtraq_id(53419);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-15 13:58:42 +0530 (Tue, 15 May 2012)");
  script_name("Adobe Flash Professional JPG Object Processing BOF Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/81753");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47116/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027045");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-12.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Professional on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_flash_professional_detect_win.nasl");
  script_require_keys("Adobe/Flash/Prof/Win/Ver");
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
flashVer = "";

flashVer = get_kb_item("Adobe/Flash/Prof/Win/Ver");
if(!flashVer){
  exit(0);
}

flashVer = eregmatch(pattern:"CS[0-9.]+ ([0-9.]+)", string:flashVer);
if(flashVer[1])
{
  ## Check for Adobe Flash Professional version
  if(version_is_less_equal(version:flashVer[1], test_version:"11.5.1.349")){
    security_hole(0);
  }
}
