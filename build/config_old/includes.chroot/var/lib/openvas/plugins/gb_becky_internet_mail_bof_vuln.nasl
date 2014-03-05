###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_becky_internet_mail_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Becky! Internet Mail Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will allow a remote attacker to execute arbitrary
  code on the target system and can cause denial-of-service condition.

  Impact level: Application";

tag_affected = "Becky! Internet Mail version 2.48.2 and prior on Windows.";
tag_insight = "The flaw is generated when the application fails to perform adequate boundary
  checks on user-supplied input. Boundary error may be generated when the user
  agrees to return a receipt message for a specially crafted e-mail thus
  leading to buffer overflow.";
tag_solution = "Update to version 2.50.01 or later
  http://www.rimarts.co.jp/becky.htm";
tag_summary = "This host is running Becky! Internet Mail client which is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(800519);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0569");
  script_bugtraq_id(33756);
  script_name("Becky! Internet Mail Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33892");
  script_xref(name : "URL" , value : "http://www.rimarts.jp/downloads/B2/Readme-e.txt");

  script_description(desc);
  script_summary("Check for the version of Becky! Internet Mail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_becky_internet_mail_detect.nasl");
  script_require_keys("Becky/InternetMail/Ver");
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

bimVer = get_kb_item("Becky/InternetMail/Ver");
if(bimVer == NULL){
  exit(0);
}

# Grep for version 2.48.02 (2.4.8.2)
if(version_is_less_equal(version:bimVer, test_version:"2.4.8.2")){
  security_hole(0);
}
