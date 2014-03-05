###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_pdf_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Adobe Acrobat PDF File Denial Of Service Vulnerability
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
tag_impact = "Successful attacks results in Denial of Service.
  Impact Level: Application";
tag_affected = "Adobe Acrobat version 9.1.1 and prior on Windows.";
tag_insight = "A Stack consumption error exists when handling a PDF file containing a large
  number of '[' characters to the alert method.";
tag_solution = "Upgrade to Adobe Acrobat version 9.1.2 or later,
  For updates refer to http://www.adobe.com/products/acrobat/?promoid=BPDDU";
tag_summary = "This host has Adobe Acrobat or Adobe Acrobat Reader installed and
  is prone to Denial of Service vulnerability.";

if(description)
{
  script_id(801104);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3431");
  script_bugtraq_id(35148);
  script_name("Adobe Acrobat PDF File Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2009-3431");

  script_description(desc);
  script_summary("Check for the version of Adobe Acrobat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_require_keys("Adobe/Acrobat/Win/Ver");
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

# Check for Adobe Acrobat version <= 9.1.1
acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer)
{
  if(version_is_less_equal(version:acrobatVer, test_version:"9.1.1"))
  {
    security_warning(0);
    exit(0);
  }
}
