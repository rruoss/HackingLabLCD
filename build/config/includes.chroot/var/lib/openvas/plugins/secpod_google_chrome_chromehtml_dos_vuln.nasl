###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_chromehtml_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Google Chrome 'chromehtml: URI Denial Of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful attacks could allows remote attackers to cause application hang
  and CPU consumption which may result in Denial of Service condition.
  Impact Level: Application";
tag_affected = "Google Chrome version 1.0.154.65 and prior on Windows.";
tag_insight = "Error occurs when vectors involving a series of function calls that set a
  'chromehtml:' URI value for the document.location property.";
tag_solution = "Upgrade to Google Chrome version 4.1.249.1064 or later.
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_id(900833);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2974");
  script_name("Google Chrome 'chromehtml: URI' Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3435/");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2009-08/0236.html");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2009-08/0217.html");

  script_description(desc);
  script_summary("Check for the Version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
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

# Get for Chrome Version
chromeVer = get_kb_item("GoogleChrome/Win/Ver");

if(isnull(chromeVer)){
  exit(0);
}

# Check for Google Chrome version < 1.0.154.65
if(version_is_less_equal(version:chromeVer, test_version:"1.0.154.65")){
  security_warning(0);
  exit(0);
}
