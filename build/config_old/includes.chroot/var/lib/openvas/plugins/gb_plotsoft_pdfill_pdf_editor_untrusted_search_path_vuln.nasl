###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plotsoft_pdfill_pdf_editor_untrusted_search_path_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PlotSoft PDFill PDF Editor Untrusted Search Path Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow local users to gain privileges via a
  Trojan horse mfc70enu.dll or mfc80loc.dll in the current working directory.
  Impact Level: Application";
tag_affected = "PlotSoft PDFill PDF Editor version 8.0";

tag_insight = "The flaw is due to untrusted search path vulnerability, which allows
  local users to gain privileges.";
tag_solution = "No solution or patch is available as of 4th October, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.pdfill.com/download.html";
tag_summary = "This host is installed with PlotSoft PDFill PDF Editor and is
  prone to untrusted search path vulnerability.";

if(description)
{
  script_id(802177);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2011-3690");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("PlotSoft PDFill PDF Editor Untrusted Search Path Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2011-3690");
  script_xref(name : "URL" , value : "http://olex.openlogic.com/wazi/2011/pdfill-pdf-editor-8-0-medium/");

  script_description(desc);
  script_summary("Check for the version of PlotSoft PDFill PDF Editor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_plotsoft_pdfill_pdf_editor_detect.nasl");
  script_require_keys("PlotSoft/PDFill/PDF/Editor/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");

## Get the version from KB
pdfVer = get_kb_item("PlotSoft/PDFill/PDF/Editor/Ver");
if(!pdfVer){
  exit(0);
}

## Check for PlotSoft PDFill PDF Editor version
if(version_is_equal(version:pdfVer, test_version:"8.0")){
  security_hole(0);
}
