###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_unspecified_oct10_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Reader Multiple Unspecified Vulnerabilities -Oct10 (Linux)
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
tag_impact = "Successful exploitation will let attackers to gain privileges via unknown
  vectors.
  Impact Level:Application";
tag_affected = "Adobe Reader version 8.x before 8.2.5 and 9.x before 9.4 on linux";
tag_insight = "An unspecified flaw is present in the application which can be exploited
  through an unknown attack vectors.";
tag_solution = "Upgrade to Adobe Reader version 9.4 or 8.2.5
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Reader and is prone to multiple
  unspecified vulnerabilities.";

if(description)
{
  script_id(801525);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_cve_id("CVE-2010-2887");
  script_bugtraq_id(43740);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities -Oct10 (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41435/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2573");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-21.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_require_keys("Adobe/Reader/Linux/Version");
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

readerVer = get_kb_item("Adobe/Reader/Linux/Version");
if(!readerVer){
  exit(0);
}

# Check for Adobe Reader version < 8.2.5 and 9.x to 9.3.4
if(version_is_less(version:readerVer, test_version:"8.2.5") ||
   version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.3.4")){
  security_hole(0);
}
