###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox-3.0, xulrunner-1.9 regression USN-645-3
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
tag_insight = "USN-645-1 fixed vulnerabilities in Firefox and xulrunner. The upstream
  patches introduced a regression in the saved password handling. While
  password data was not lost, if a user had saved any passwords with
  non-ASCII characters, Firefox could not access the password database.
  This update fixes the problem.

  We apologize for the inconvenience.
  
  Original advisory details:
  
  Justin Schuh, Tom Cross and Peter Williams discovered errors in the
  Firefox URL parsing routines. If a user were tricked into opening a
  crafted hyperlink, an attacker could overflow a stack buffer and
  execute arbitrary code. (CVE-2008-0016)
  
  It was discovered that the same-origin check in Firefox could be
  bypassed. If a user were tricked into opening a malicious website,
  an attacker may be able to execute JavaScript in the context of a
  different website. (CVE-2008-3835)
  
  Several problems were discovered in the JavaScript engine. This
  could allow an attacker to execute scripts from page content with
  chrome privileges. (CVE-2008-3836)
  
  Paul Nickerson discovered Firefox did not properly process mouse
  click events. If a user were tricked into opening a malicious web
  page, an attacker could move the content window, which could
  potentially be used to force a user to perform unintended drag and
  drop operations. (CVE-2008-3837)
  
  Several problems were discovered in the browser engine. This could
  allow an attacker to execute code with chrome privileges.
  (CVE-2008-4058, CVE-2008-4059, CVE-2008-4060)
  
  Drew Yao, David Maciejak and other Mozilla developers found several
  problems in the browser engine of Firefox. If a user were tricked
  into opening a malicious web page, an attacker could cause a denial
  of service or possibly execute arbitrary code with the privileges
  of the user invoking the program. (CVE-2008-4061, CVE-2008-4062,
  CVE-2008-4063, CVE-2008-4064)
  
  Dave Reed discovered a flaw in the JavaScript parsing code when
  processing certain BOM characters. An attacker could exploit this
  to bypass script filters and perform cross-site scripting attacks.
  (CVE-2008-4065)
  
  Gareth Heyes discovered a flaw in the HTML parser of Firefox. If a
  user were tricked into opening a malicious web page, an attacker
  could bypass script filtering and perform cross-site scripting
  attacks. (CVE-2008-4066)
  
  Boris Zbarsky and Georgi Guninski independently discovered flaws in
  the resource: protocol. An attacker could exploit this to perform
  directory traversal, read information about the system, and prompt
  the user to save ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-645-3";
tag_affected = "firefox-3.0, xulrunner-1.9 regression on Ubuntu 8.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-September/000753.html");
  script_id(840352);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "645-3");
  script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069");
  script_name( "Ubuntu Update for firefox-3.0, xulrunner-1.9 regression USN-645-3");

  script_description(desc);
  script_summary("Check for the Version of firefox-3.0, xulrunner-1.9 regression");
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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0-dev_3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0-gnome-support_3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0_3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.9-dev_1.9.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.9-gnome-support_1.9.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.9_1.9.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0-dom-inspector_3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0-venkman_3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dom-inspector", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-dom-inspector", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-venkman", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.9-dom-inspector_1.9.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.9-venkman_1.9.0.3+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
