###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_firefox_spoofing_vuln_win_jun10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Firefox Address Bar Spoofing Vulnerability june-10 (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to conduct spoofing attacks.
  Impact Level: Application";
tag_affected = "Firefox version before 3.6.6";
tag_insight = "The flaw is due to error in the 'startDocumentLoad()' function in
  'browser/base/content/browser.js', fails to implement Same Origin Policy.
  This can be exploited to display arbitrary content in the blank document
  while showing the URL of a trusted web site in the address bar.";
tag_solution = "Upgrade to Firefox version 3.6.6 or later,
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox and is prone to spoofing
  vulnerability.";

if(description)
{
  script_id(902209);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-02 08:02:13 +0200 (Fri, 02 Jul 2010)");
  script_cve_id("CVE-2010-1206");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Mozilla Firefox Address Bar Spoofing Vulnerability june-10 (Win)");
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
  script_summary("Check for the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40283");
  script_xref(name : "URL" , value : "http://hg.mozilla.org/mozilla-central/rev/cadddabb1178");
  script_xref(name : "URL" , value : "http://lcamtuf.blogspot.com/2010/06/yeah-about-that-address-bar-thing.html");
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version < 3.6.6
  if(version_is_less(version:ffVer, test_version:"3.6.6")){
    security_warning(0);
  }
}
