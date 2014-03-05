###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuance_pdf_reader_mult_memory_corruption_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Nuance PDF Reader Multiple Memory Corruption Vulnerabilities
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
tag_impact = "Successful exploitation allows an attacker to corrupt memory, execute
  arbitrary code within the context of the user running the affected
  application or failed attempts may cause a denial-of-service.
  Impact Level: System/Application";

tag_affected = "Nuance PDF Reader version 7.0";
tag_insight = "Multiple unspecified flaws as user input is not properly sanitized when
  handling PDF files.";
tag_solution = "No solution or patch is available as of 11th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.nuance.com/products/pdf-reader/index.htm";
tag_summary = "The host is installed with Nuance PDF Reader and is prone to
  multiple memory-corruption vulnerabilities.";

if(description)
{
  script_id(803329);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57851);
  script_cve_id("CVE-2013-0113");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-11 15:51:39 +0530 (Mon, 11 Mar 2013)");
  script_name("Nuance PDF Reader Multiple Memory Corruption Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.com/90176");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/248449");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/438057.php");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/cve_reference/CVE-2013-0113");

  script_description(desc);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check the vulnerable version of Nuance PDF Reader on Windows");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_nuance_pdf_reader_detect_win.nasl");
  script_mandatory_keys("Nuance/PDFReader/Win/Ver");
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
ReaderVer ="";

# Get the version from KB
ReaderVer = get_kb_item("Nuance/PDFReader/Win/Ver");

# Check for Nuance PDF Editor Version
if(ReaderVer && ReaderVer == "7.00.0000")
{
  security_hole(0);
  exit(0);
}
