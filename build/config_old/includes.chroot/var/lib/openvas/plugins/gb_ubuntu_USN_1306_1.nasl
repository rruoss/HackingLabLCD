###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-1306-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "Alexandre Poirot, Chris Blizzard, Kyle Huey, Scoobidiver, Christian Holler,
  David Baron, Gary Kwong, Jim Blandy, Bob Clary, Jesse Ruderman, Marcia
  Knous, and Rober Longson discovered several memory safety issues which
  could possibly be exploited to crash Firefox or execute arbitrary code as
  the user that invoked Firefox. (CVE-2011-3660)

  Aki Helin discovered a crash in the YARR regular expression library that
  could be triggered by javascript in web content. (CVE-2011-3661)

  It was discovered that a flaw in the Mozilla SVG implementation could
  result in an out-of-bounds memory access if SVG elements were removed
  during a DOMAttrModified event handler. An attacker could potentially
  exploit this vulnerability to crash Firefox. (CVE-2011-3658)

  Mario Heiderich discovered it was possible to use SVG animation accessKey
  events to detect key strokes even when JavaScript was disabled. A malicious
  web page could potentially exploit this to trick a user into interacting
  with a prompt thinking it came from the browser in a context where the user
  believed scripting was disabled. (CVE-2011-3663)

  It was discovered that it was possible to crash Firefox when scaling an OGG
  &lt;video&gt; element to extreme sizes. (CVE-2011-3665)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1306-1";
tag_affected = "firefox on Ubuntu 11.04";
tag_solution = "Please Install the Updated Packages.";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-January/001541.html");
  script_id(840857);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-09 13:29:54 +0530 (Mon, 09 Jan 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1306-1");
  script_cve_id("CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3658", "CVE-2011-3663", "CVE-2011-3665");
  script_name("Ubuntu Update for firefox USN-1306-1");

  script_description(desc);
  script_summary("Check for the Version of firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"9.0.1+build1-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
