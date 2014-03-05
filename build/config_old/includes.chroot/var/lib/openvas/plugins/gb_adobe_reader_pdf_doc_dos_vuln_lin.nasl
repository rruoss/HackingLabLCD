###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_pdf_doc_dos_vuln_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Reader PDF Handling Denial Of Service Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code or
  cause a denial of service via a crafted PDF document.

  Impact level: System/Application.";

tag_affected = "Adobe Reader version 9.3.1 on Linux.";
tag_insight = "The flaw is due to an error in 'custom heap management system', allows the
  attackers to execute arbitrary code via a crafted program that is specified
  in a PDF document.";
tag_solution = "Upgrade to Adobe Reader version 9.3.2 or later,
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Reader and is prone to Denial of
  Service vulnerability.";

if(description)
{
  script_id(801305);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_cve_id("CVE-2010-1241");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Reader PDF Handling Denial Of Service Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://blog.didierstevens.com/2010/03/29/escape-from-pdf/");
  script_xref(name : "URL" , value : "http://www.blackhat.com/html/bh-eu-10/bh-eu-10-briefings.html#Li");
  script_xref(name : "URL" , value : "http://lists.immunitysec.com/pipermail/dailydave/2010-April/006075.html");
  script_xref(name : "URL" , value : "http://lists.immunitysec.com/pipermail/dailydave/2010-April/006077.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_require_keys("Adobe/Reader/Linux/Version");
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

readerVer = get_kb_item("Adobe/Reader/Linux/Version");
if(readerVer != NULL)
{
  # Grep for Adobe Reader version 9.3.1
  if(version_is_equal(version:readerVer, test_version:"9.3.1")){
     security_hole(0);
  }
}
