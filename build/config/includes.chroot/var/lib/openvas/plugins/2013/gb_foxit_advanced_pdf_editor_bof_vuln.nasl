###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_advanced_pdf_editor_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Foxit Advanced PDF Editor Buffer Overflow Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows an attacker to execute arbitrary code or
  cause a denial-of-service.
  Impact Level: System/Application";

tag_affected = "Foxit Advanced PDF Editor Version 3.x before 3.04";
tag_insight = "The flaw caused due to stack buffer overflow, which allow attackers to
  execute arbitrary code via a crafted document containing instructions that
  reconstruct a certain security cookie.";
tag_solution = "Upgrade to the Foxit Advanced PDF Editor version 3.04 or later,
  For updates refer to http://www.foxitsoftware.com/downloads";
tag_summary = "The host is installed with Foxit Advanced PDF Editor and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(803304);
  script_version("$Revision: 11 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-01 19:35:22 +0530 (Fri, 01 Feb 2013)");
  script_bugtraq_id(57558);
  script_cve_id("CVE-2013-0107");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Foxit Advanced PDF Editor Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/275219");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2013-0107");

  script_description(desc);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check the vulnerable version of Foxit Advanced PDF Editor");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_foxit_advanced_pdf_editor_detect_win.nasl");
  script_require_keys("Foxit/AdvancedEditor/Win/Ver");
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

# Variable Initialization
foxitVer ="";

# Get the version from KB
foxitVer = get_kb_item("Foxit/AdvancedEditor/Win/Ver");

# Check for Foxit Advanced PDF Editor Version
# If we install 3.04, it takes 3.0.4.0
if(foxitVer && foxitVer =~ "^3")
{
  if(version_is_less(version: foxitVer, test_version: "3.0.4.0")){
    security_hole(0);
    exit(0);
  }
}
