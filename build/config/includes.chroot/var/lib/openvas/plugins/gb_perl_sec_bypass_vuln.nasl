###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_sec_bypass_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Perl Laundering Security Bypass Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to bypass security checks in
  perl applications that rely on TAINT mode protection functionality.
  Impact Level: Application";
tag_affected = "Perl version 5.10.x, 5.11.x, 5.12.x to 5.12.3 and 5.13.x to 5.13.11 on Windows.";
tag_insight = "The flaw is due to the 'uc()', 'lc()', 'lcfirst()', and 'ucfist()'
  functions incorrectly laundering tainted data, which can result in the
  unintended use of potentially malicious data after using these functions.";
tag_solution = "Upgrade to Perl version 5.14 or later.
  For updates refer to http://www.perl.org/get.html";
tag_summary = "The host is installed with Perl and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(801771);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-1487");
  script_bugtraq_id(47124);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Perl Laundering Security Bypass Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43921");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66528");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2011/04/04/35");

  script_description(desc);
  script_summary("Check for the version of Perl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_perl_detect_win.nasl");
  script_require_keys("Strawberry/Perl/Ver", "ActivePerl/Ver");
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

apVer = get_kb_item("ActivePerl/Ver");
if(apVer)
{
  if((apVer =~ "^5\.10") || (apVer =~ "^5\.11") ||
     version_in_range(version:apVer, test_version:"5.12", test_version2:"5.12.3") ||
     version_in_range(version:apVer, test_version:"5.13", test_version2:"5.13.11"))
  {
    security_warning(0);
    exit(0);
  }
}

spVer = get_kb_item("Strawberry/Perl/Ver");
if(spVer)
{
  if((spVer =~ "^5\.10") || (spVer =~ "^5\.11") ||
     version_in_range(version:spVer, test_version:"5.12", test_version2:"5.12.3") ||
     version_in_range(version:spVer, test_version:"5.13", test_version2:"5.13.11")){
    security_warning(0);
  }
}
