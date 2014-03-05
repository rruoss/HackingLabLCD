###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_code_exec_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Foxit Reader Arbitrary Command Execution Vulnerability
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
tag_impact = "Successful exploitation will let attacker to execute arbitrary code or crash an
  affected application.
  Impact Level: Application";
tag_affected = "Foxit Reader version prior to 3.2.1.0401";
tag_insight = "The flaw exists due to error in hadling 'PDF' files which runs executable
  embedded program inside a PDF automatically without asking for user permission.";
tag_solution = "Upgrade to the version 3.2.1.0401 or later,
  For updates refer to http://www.foxitsoftware.com/downloads/";
tag_summary = "The host is installed with Foxit Reader and is prone to
  arbitrary command execution vulnerability.";

if(description)
{
  script_id(801313);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-1239");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Foxit Reader Arbitrary Command Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/570177");
  script_xref(name : "URL" , value : "http://www.foxitsoftware.com/pdf/reader/security.htm#0401");
  script_xref(name : "URL" , value : "http://blog.didierstevens.com/2010/03/29/escape-from-pdf/");
  script_xref(name : "URL" , value : "http://blog.didierstevens.com/2010/03/31/escape-from-foxit-reader/");

  script_description(desc);
  script_summary("Check for the version of Foxit Reader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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
if(foxVer)
{
  if(version_is_less(version:foxVer,test_version:"3.2.1.0401")){
    security_hole(0);
  }
}
