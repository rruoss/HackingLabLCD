###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_mult_vuln_nov09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mozilla Firefox Multiple Vulnerabilities Nov-09 (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will let attacker to disclose sensitive information,
  bypass certain security restrictions, manipulate certain data, or compromise
  a user's system.
  Impact Level: Application/System";
tag_affected = "Firefox version 3.0 before 3.0.15 and 3.5 before 3.5.4 on Windows.";
tag_insight = "Muliple flaw are due to following errors,
  - An array indexing error exists when allocating space for floating point
    numbers. This can be exploited to trigger a memory corruption when a
    specially crafted floating point number is processed.
  - An error in the form history functionality can be exploited to disclose
    history entries via a specially crafted web page that triggers the automatic
    filling of form fields.
  - When parsing regular expressions used in Proxy Auto-configuration. This can
    be exploited to cause a crash or potentially execute arbitrary code via
    specially crafted configured PAC files.
  - When processing GIF, color maps can be exploited to cause a heap based
    buffer overflow and potentially execute arbitrary code via a specially
    crafted GIF file.
  - An error in the 'XPCVariant::VariantDataToJS()' XPCOM utility, which can be
    exploited to execute arbitrary JavaScript code with chrome privileges.
  - An error in the implementation of the JavaScript 'document.getSelection()'
    can be exploited to read text selected on a web page in a different domain.
  - An error when downloading files can be exploited to display different file
    names in the download dialog title bar and download dialog body. This can
    be exploited to obfuscate file names via a right-to-left override character
    and potentially trick a user into running an executable file.
  - Multiple unspecified errors in the browser engines can be exploited to cause
    crash or potentially execute arbitrary code.";
tag_solution = "Upgrade to Firefox version 3.0.15 or 3.5.4
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "This host is installed with Mozilla Firefox browser and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801130);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3370", "CVE-2009-3373", "CVE-2009-3372", "CVE-2009-0689",
                "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3380");
  script_bugtraq_id(36851, 36853, 36856, 36855, 36857, 36858, 36867, 36871);
  script_name("Mozilla Firefox Multiple Vulnerabilities Nov-09 (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2009-35/");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-52.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-55.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-56.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-57.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-59.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-61.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-62.html");

  script_description(desc);
  script_summary("Check for the version of Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
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

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

# Check for Firefox version 3.0 < 3.0.15 or 3.5 < 3.5.4
if(version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.14")||
   version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.3")) {
  security_hole(0);
}
