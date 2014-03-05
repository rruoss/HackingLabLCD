###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_7zip_archive_handling_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# 7-Zip Unspecified Archive Handling Vulnerability (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary code in the
  affected system and cause denial of service.";
tag_affected = "7zip version prior to 4.57 on Linux";
tag_insight = "This flaw occurs due to memory corruption while handling malformed archives.";
tag_solution = "Upgrade to 7zip version 4.57
  http://www.7-zip.org";
tag_summary = "This host is installed with 7zip and is prone to Unspecified
  vulnerability.";

if(description)
{
  script_id(800256);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-6536");
  script_bugtraq_id(28285);
  script_name("7-Zip Unspecified Archive Handling Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/29434");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/0914/references");
  script_xref(name : "URL" , value : "http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html");

  script_description(desc);
  script_summary("Check for the version of 7zip (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_7zip_detect_lin.nasl");
  script_require_keys("7zip/Lin/Ver");
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

zipVer = get_kb_item("7zip/Lin/Ver");
if(!zipVer){
  exit(0);
}

# Grep for 7zip version prior to 4.57
if(version_is_less(version:zipVer, test_version:"4.57")){
  security_hole(0);
}
