###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mailto_dos_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Products Denial of Service Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_solution = "Upgrade to Firefox version 3.5.9 or 3.6.2
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Seamonkey version 2.0.4
  http://www.seamonkey-project.org/releases/";

tag_impact = "Successful exploitation will let attackers to cause a denial of service
  (excessive application launches) via an HTML document with many images.
  Impact Level: Application";
tag_affected = "Seamonkey version prior to 2.0.4 and
  Firefox version before 3.5.9, 3.6.x before 3.6.2 on Windows.";
tag_insight = "The flaw is caused by an error when handling an 'image' tag pointing to
  a resource that redirects to a 'mailto:' URL, an external mail handler
  application is launched.";
tag_summary = "The host is installed with Mozilla Firefox/Seamonkey and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_id(800750);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-0181");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Mozilla Products Denial of Service Vulnerability (Windows)");
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

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57395");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0748");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-23.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Seamonkey/Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_seamonkey_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver", "Seamonkey/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version< 3.5.9 and 3.6 < 3.6.2
  if(version_is_less(version:ffVer, test_version:"3.5.9") ||
     version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.1"))
     {
       security_warning(0);
       exit(0);
     }
}

# Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  # Grep for Seamonkey version < 2.0.4
  if(version_is_less(version:smVer, test_version:"2.0.4")){
    security_warning(0);
  }
}
