###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ston3d_prdts_code_exec_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# StoneTrip Ston3D Products Code Execution Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary
  codes in the context of the application via shell metacharacters in the
  'sURL' argument.";
tag_affected = "StoneTrip Ston3D Standalone Player version 1.6.2.4 and 1.7.0.1,
  StoneTrip Ston3D Web Player version 1.6.0.0 on Windows.";
tag_insight = "The flaw is generated due to inadequate sanitation of user supplied data
  used in the 'system.openURL()' fuction.";
tag_solution = "No solution or patch is available as of 01st June, 2009.Information
  regarding this issue will be updated once the solution details are
  available. For updates refer to http://www.stonetrip.com/";
tag_summary = "This host is installed with StoneTrip Ston3D products and is prone
  to Code Execution vulnerability.";

if(description)
{
  script_id(800574);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1792");
  script_bugtraq_id(35105);
  script_name("StoneTrip Ston3D Products Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/StoneTrip-S3DPlayers");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/503887/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of StoneTrip Ston3D Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ston3d_prdts_detect_win.nasl");
  script_require_keys("Ston3D/Web/Player/Ver",
                      "Ston3D/Standalone/Player/Win/Ver");
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

wpVer = get_kb_item("Ston3D/Web/Player/Ver");
if((wpVer) && (version_is_equal(version:wpVer, test_version:"1.6.0.0")))
{
  security_hole(0);
  exit(0);
}

sapVer = get_kb_item("Ston3D/Standalone/Player/Win/Ver");
if(sapVer){
  if((version_is_equal(version:sapVer, test_version:"1.6.2.4")) ||
     (version_is_equal(version:sapVer, test_version:"1.7.0.1"))){
    security_hole(0);
  }
}
