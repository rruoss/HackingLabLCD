###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_maketext_mult_code_inje_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Strawberry Perl Locale::Maketext Module Multiple Code Injection Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code on
  the system.
  Impact Level: System/Application";

tag_affected = "Strawberry Perl version prior to 5.17.7 on Windows";
tag_insight = "An improper validation of input by the '_compile()' function which can be
  exploited to inject and execute arbitrary Perl code on the system.";
tag_solution = "Upgrade to Strawberry Perl version 5.17.7 or later,
  For updates refer to http://strawberryperl.com";
tag_summary = "The host is installed with Strawberry Perl and is prone to multiple code
  injection vulnerabilities.";

if(description)
{
  script_id(803162);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-6329");
  script_bugtraq_id(56852);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-24 12:42:04 +0530 (Thu, 24 Jan 2013)");
  script_name("Strawberry Perl Locale::Maketext Module Multiple Code Injection Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/88272");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51498");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80566");
  script_summary("Check for the vulnerable version of Strawberry Perl on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Strawberry/Perl/Ver");
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

## Variable Initialization
spVer = "";

## Get version from KB
spVer = get_kb_item("Strawberry/Perl/Ver");
if(spVer)
{
  if(version_is_less(version:spVer, test_version:"5.17.7"))
  {
    security_hole(0);
    exit(0);
  }
}
