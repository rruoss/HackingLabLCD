###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for Firefox and Xulrunner vulnerabilities USN-1049-1
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "Jesse Ruderman, Igor Bukanov, Olli Pettay, Gary Kwong, Jeff Walden, Henry
  Sivonen, Martijn Wargers, David Baron and Marcia Knous discovered several
  memory issues in the browser engine. An attacker could exploit these to
  crash the browser or possibly run arbitrary code as the user invoking the
  program. (CVE-2011-0053, CVE-2011-0062)

  Zach Hoffman discovered that a recursive call to eval() wrapped in a
  try/catch statement places the browser into a inconsistent state. An
  attacker could exploit this to force a user to accept any dialog.
  (CVE-2011-0051)
  
  It was discovered that memory was used after being freed in a method used
  by JSON.stringify. An attacker could exploit this to crash the browser or
  possibly run arbitrary code as the user invoking the program.
  (CVE-2011-0055)
  
  Christian Holler discovered multiple buffer overflows in the JavaScript
  engine. An attacker could exploit these to crash the browser or possibly
  run arbitrary code as the user invoking the program. (CVE-2011-0054,
  CVE-2011-0056)
  
  Daniel Kozlowski discovered that a JavaScript Worker kept a reference to
  memory after it was freed. An attacker could exploit this to crash the
  browser or possibly run arbitrary code as the user invoking the program.
  (CVE-2011-0057)
  
  Alex Miller discovered a buffer overflow in the browser rendering engine.
  An attacker could exploit this to crash the browser or possibly run
  arbitrary code as the user invoking the program. (CVE-2011-0058)
  
  Roberto Suggi Liverani discovered a possible issue with unsafe JavaScript
  execution in chrome documents. A malicious extension could exploit this to
  execute arbitrary code with chrome privlieges. (CVE-2010-1585)
  
  Jordi Chancel discovered a buffer overlow in the JPEG decoding engine. An
  attacker could exploit this to crash the browser or possibly run arbitrary
  code as the user invoking the program. (CVE-2011-0061)
  
  Peleus Uhley discovered a CSRF vulnerability in the plugin code related to
  307 redirects. This could allow custom headers to be forwarded across
  origins. (CVE-2011-0059)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1049-1";
tag_affected = "Firefox and Xulrunner vulnerabilities on Ubuntu 8.04 LTS ,
  Ubuntu 9.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 10.10";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-March/001270.html");
  script_id(840604);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1049-1");
  script_cve_id("CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059", "CVE-2011-0061", "CVE-2011-0062");
  script_name("Ubuntu Update for Firefox and Xulrunner vulnerabilities USN-1049-1");

  script_description(desc);
  script_summary("Check for the Version of Firefox and Xulrunner vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"abrowser-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-dbg", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-gnome-support", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-testsuite-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-testsuite", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser-3.5-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2-dom-inspector", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2-libthai", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.1-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.1-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.5-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.5-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.5-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.5-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.5", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser-3.0-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser-3.0", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser-3.1-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser-3.1", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser-3.5", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-dom-inspector", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-venkman", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.1-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.1-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.1", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"firefox-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-dbg", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-testsuite-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-mozsymbols", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-gnome-support", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-testsuite", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-mozsymbols", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-dbg", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-testsuite-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-gnome-support", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-testsuite", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.5-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.5-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser-3.5-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser-3.5", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2-dom-inspector", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2-libthai", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-2", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.5-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.5-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.5", ver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"abrowser-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-branding", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support-dbg", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-dbg", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-gnome-support", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-testsuite-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9.2-testsuite", ver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
