###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox-3.0, xulrunner-1.9 vulnerabilities USN-626-1
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "A flaw was discovered in the browser engine. A variable could be made to
  overflow causing the browser to crash. If a user were tricked into opening
  a malicious web page, an attacker could cause a denial of service or
  possibly execute arbitrary code with the privileges of the user invoking
  the program. (CVE-2008-2785)

  Billy Rios discovered that Firefox and xulrunner, as used by browsers
  such as Epiphany, did not properly perform URI splitting with pipe
  symbols when passed a command-line URI. If Firefox or xulrunner were
  passed a malicious URL, an attacker may be able to execute local
  content with chrome privileges. (CVE-2008-2933)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-626-1";
tag_affected = "firefox-3.0, xulrunner-1.9 vulnerabilities on Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-July/000735.html");
  script_id(840327);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "626-1");
  script_cve_id("CVE-2008-2785", "CVE-2008-2933", "CVE-2008-2934");
  script_name( "Ubuntu Update for firefox-3.0, xulrunner-1.9 vulnerabilities USN-626-1");

  script_description(desc);
  script_summary("Check for the Version of firefox-3.0, xulrunner-1.9 vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0-dev_3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0-gnome-support_3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0_3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.9-dev_1.9.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.9-gnome-support_1.9.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.9_1.9.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0-dom-inspector_3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0-venkman_3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dom-inspector", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-dom-inspector", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-venkman", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.9-dom-inspector_1.9.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.9-venkman_1.9.0.1+build1+nobinonly-0ubuntu0.8.04.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
