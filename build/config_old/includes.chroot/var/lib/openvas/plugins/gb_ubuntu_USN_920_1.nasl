###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for Firefox 3.0 and Xulrunner vulnerabilities USN-920-1
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "Martijn Wargers, Josh Soref, Jesse Ruderman, and Ehsan Akhgari discovered
  flaws in the browser engine of Firefox. If a user were tricked into viewing
  a malicious website, a remote attacker could cause a denial of service or
  possibly execute arbitrary code with the privileges of the user invoking
  the program. (CVE-2010-0174)

  It was discovered that Firefox could be made to access previously freed
  memory. If a user were tricked into viewing a malicious website, a remote
  attacker could cause a denial of service or possibly execute arbitrary code
  with the privileges of the user invoking the program. (CVE-2010-0175,
  CVE-2010-0176, CVE-2010-0177)
  
  Paul Stone discovered that Firefox could be made to change a mouse click
  into a drag and drop event. If the user could be tricked into performing
  this action twice on a crafted website, an attacker could execute
  arbitrary JavaScript with chrome privileges. (CVE-2010-0178)
  
  It was discovered that the XMLHttpRequestSpy module as used by the Firebug
  add-on could be used to escalate privileges within the browser. If the user
  had the Firebug add-on installed and were tricked into viewing a malicious
  website, an attacker could potentially run arbitrary JavaScript.
  (CVE-2010-0179)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-920-1";
tag_affected = "Firefox 3.0 and Xulrunner vulnerabilities on Ubuntu 8.04 LTS ,
  Ubuntu 8.10 ,
  Ubuntu 9.04";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2010-April/001077.html");
  script_id(840418);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-16 17:02:11 +0200 (Fri, 16 Apr 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "920-1");
  script_cve_id("CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178", "CVE-2010-0179");
  script_name("Ubuntu Update for Firefox 3.0 and Xulrunner vulnerabilities USN-920-1");

  script_description(desc);
  script_summary("Check for the Version of Firefox 3.0 and Xulrunner vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "UBUNTU9.04")
{

  if ((res = isdpkgvuln(pkg:"abrowser-3.0-branding", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-branding", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dev", ver:"1.9.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-venkman", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-venkman", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dom-inspector", ver:"1.9.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-venkman", ver:"1.9.0.19+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.10")
{

  if ((res = isdpkgvuln(pkg:"abrowser-3.0-branding", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-branding", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dev", ver:"1.9.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"abrowser", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-venkman", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-venkman", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dom-inspector", ver:"1.9.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-venkman", ver:"1.9.0.19+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dev", ver:"1.9.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-3.0-venkman", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-dom-inspector", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk-venkman", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dom-inspector", ver:"1.9.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xulrunner-1.9-venkman", ver:"1.9.0.19+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
