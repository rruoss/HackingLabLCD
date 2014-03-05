###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_security_bypass_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Firefox Security Bypass Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to bypass cross-site scripting
  protection mechanisms via a crafted string.
  Impact Level: Application";
tag_affected = "Mozilla Firefox versions prior to 3.6 Beta 3.";
tag_insight = "The flaw is due to improper validation of overlong UTF-8 encoding,
  which makes it easier for remote attackers to bypass cross-site scripting
  protection mechanisms via a crafted string.";
tag_solution = "Upgrade to Mozilla Firefox version 3.6 Beta 3 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/upgrade.html";
tag_summary = "The host is installed with Mozilla Firefox and is prone to security
  bypass vulnerability.";

if(description)
{
  script_id(801637);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_cve_id("CVE-2009-5017");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Mozilla Firefox Security Bypass Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=511859");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=522634");
  script_xref(name : "URL" , value : "http://sirdarckcat.blogspot.com/2009/10/couple-of-unicode-issues-on-php-and.html");

  script_description(desc);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_summary("Check the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
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

## Get Firefox version from KB
fpVer = get_kb_item("Firefox/Win/Ver");
if(!fpVer){
  exit(0);
}

## Check for Mozilla Firefox Versions
if(version_in_range(version:fpVer, test_version:"3.6.b1", test_version2:"3.6.b2")){
  security_warning(0);
}
