###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_mult_vuln_mar09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Foxit Reader Multiple Vulnerabilities Mar-09
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
tag_impact = "Successful exploitation will let attacker execute arbitrary code via
  relative and absolute paths and to dereference uninstalled memory.
  Impact Level: Application";
tag_affected = "Foxit Reader 2.3 before Build 3902 and 3.0 before Build 1506.";
tag_insight = "- application does not require user confirmation before performing dangerous
    actions
  - stack based buffer overflow while processing a PDF file containing an
    action with overly long filename argument
  - error while processing JBIG2 symbol dictionary segment with zero new
    symbols";
tag_solution = "Upgrade to the latest version.
  http://www.foxitsoftware.com/downloads/";
tag_summary = "The host is installed with Foxit  Reader and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(800537);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-17 05:28:51 +0100 (Tue, 17 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0836", "CVE-2009-0837", "CVE-2009-0191");
  script_bugtraq_id(34035);
  script_name("Foxit Reader Multiple Vulnerabilities Mar-09");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/369876.php");
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-0191");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2009-0837");

  script_description(desc);
  script_summary("Check for the version of Foxit Reader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_foxit_reader_detect.nasl");
  script_require_keys("Foxit/Reader/Ver");
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

foxVer = get_kb_item("Foxit/Reader/Ver");
if(!foxVer){
  exit(0);
}

if(version_is_less(version:foxVer, test_version:"2.3.2008.3902")||
  (version_in_range(version:foxVer, test_version:"3.0",
                                    test_version2:"3.0.2009.1505"))){
  security_hole(0);
}
