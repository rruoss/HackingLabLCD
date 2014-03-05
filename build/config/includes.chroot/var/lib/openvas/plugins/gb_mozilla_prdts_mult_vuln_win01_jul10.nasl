###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win01_jul10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Products Multiple Vulnerabilitie july-10 (Windows)
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
tag_solution = "Upgrade to Firefox version 3.5.11 or 3.6.7
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Seamonkey version 2.0.6
  http://www.seamonkey-project.org/releases/";

tag_impact = "Successful exploitation will let attackers to to cause a denial of service
  or execute arbitrary code.
  Impact Level: Application";
tag_affected = "Seamonkey version 2.0.x before 2.0.6
  Firefox version 3.5.x before 3.5.11 and 3.6.x before 3.6.7";
tag_insight = "The flaws are due to:
  - An error in the 'DOM' attribute cloning routine where under certain
    circumstances an event attribute node can be deleted while another object
    still contains a reference to it.
  - An error in Mozilla's implementation of NodeIterator in which a malicious
    NodeFilter could be created which would detach nodes from the DOM tree while
    it was being traversed.
  - An error in the code used to store the names and values of plugin parameter
    elements. A malicious page could embed plugin content containing a very
    large number of parameter elements which would cause an overflow in the
    integer value counting them.
  - An error in handling of location bar could be spoofed to look like a secure
    page when the current document was served via plain text.
  - Spoofing method does not require that the resource opened in a new window
    respond with 204, as long as the opener calls window.stop() before the
    document is loaded.
  - Spoofing error occurs when opening a new window containing a resource that
    responds with an HTTP 204 (no content) and then using the reference to the
    new window to insert HTML content into the blank document.";
tag_summary = "The host is installed with Mozilla Firefox/Seamonkey that are prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801386);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_bugtraq_id(41824);
  script_cve_id("CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1206",
                "CVE-2010-1214", "CVE-2010-2751");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mozilla Products Multiple Vulnerabilitie july-10 (Windows)");
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

  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-35.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-36.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-37.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-43.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-45.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox/Seamonkey");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
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

## Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  ## Grep for Firefox version 3.5 < 3.5.11, 3.6 < 3.6.2
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.6") ||
     version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.10"))
     {
       security_hole(0);
       exit(0);
     }
}

## Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  # Grep for Seamonkey version 2.0 < 2.0.6
  if(version_in_range(version:smVer, test_version:"2.0", test_version2:"2.0.5")){
    security_hole(0);
  }
}
