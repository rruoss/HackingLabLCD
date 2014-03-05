###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mathematica_symlink_vuln_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mathematica Arbitrary File Overwriting Vulnerability (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_solution = "No solution or patch is available as of 28th March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.wolfram.com/products/mathematica/index.html

  Workaround: use command-line math instead of pretty interface.";

tag_impact = "Successful exploitation will allow attackers to create world writable
  files in normally restricted directories or corrupt restricted files via
  symlink attacks.
  Impact Level: Application";
tag_affected = "Wolfram Mathematica 7 on Linux.";
tag_insight = "The flaw is due to handling of files in the '/tmp/MathLink' directory in
  an insecure manner.";
tag_summary = "The host is running Mathematica and is prone to arbitrary file
  overwriting vulnerability.";

if(description)
{
  script_id(901117);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-2027");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Low");
  script_name("Mathematica Arbitrary File Overwriting Vulnerability (Linux)");
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


  script_description(desc);
  script_summary("Check for the version of Mathematica (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_mathematica_detect_lin.nasl");
  script_require_keys("Mathematica/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39805");
  script_xref(name : "URL" , value : "http://marc.info/?l=full-disclosure&amp;m=127380255201760&amp;w=2");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511298/100/0/threaded");
  exit(0);
}


include("version_func.inc");

## Get version from KB
mVer = get_kb_item("Mathematica/Ver");
if(!mVer){
  exit(0);
}

## Check for Mathematica Version 7
if(version_in_range(version:mVer,test_version:"7.0",test_version2:"7.0.1.0")){
  security_note(0);
}
