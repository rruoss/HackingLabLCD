###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox vulnerabilities USN-576-1
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
tag_insight = "Various flaws were discovered in the browser and JavaScript engine.
  By tricking a user into opening a malicious web page, an attacker
  could execute arbitrary code with the user's privileges.
  (CVE-2008-0412, CVE-2008-0413)

  Flaws were discovered in the file upload form control. A malicious
  website could force arbitrary files from the user's computer to be
  uploaded without consent. (CVE-2008-0414)
  
  Various flaws were discovered in the JavaScript engine. By tricking
  a user into opening a malicious web page, an attacker could escalate
  privileges within the browser, perform cross-site scripting attacks
  and/or execute arbitrary code with the user's privileges. (CVE-2008-0415)
  
  Various flaws were discovered in character encoding handling. If a
  user were ticked into opening a malicious web page, an attacker
  could perform cross-site scripting attacks. (CVE-2008-0416)
  
  Justin Dolske discovered a flaw in the password saving mechanism. By
  tricking a user into opening a malicious web page, an attacker could
  corrupt the user's stored passwords. (CVE-2008-0417)
  
  Gerry Eisenhaur discovered that the chrome URI scheme did not properly
  guard against directory traversal. Under certain circumstances, an
  attacker may be able to load files or steal session data. Ubuntu is
  not vulnerable in the default installation. (CVE-2008-0418)
  
  David Bloom discovered flaws in the way images are treated by the
  browser. A malicious website could exploit this to steal the user's
  history information, crash the browser and/or possibly execute
  arbitrary code with the user's privileges. (CVE-2008-0419)
  
  Flaws were discovered in the BMP decoder. By tricking a user into
  opening a specially crafted BMP file, an attacker could obtain
  sensitive information. (CVE-2008-0420)
  
  Michal Zalewski discovered flaws with timer-enabled security dialogs.
  A malicious website could force the user to confirm a security dialog
  without explicit consent. (CVE-2008-0591)
  
  It was discovered that Firefox mishandled locally saved plain text
  files. By tricking a user into saving a specially crafted text file,
  an attacker could prevent the browser from displaying local files
  with a .txt extension. (CVE-2008-0592)
  
  Martin Straka discovered flaws in stylesheet handling after a 302
  redirect. By tricking a user into opening a malicious web page, an
  attacker could obtain sensitive URL parameters. (CVE-2008-0593)
  
  Emil Ljungdahl and Lars-Olof Moilanen discovered that a web forgery
  warning dialog wasn't displayed under certain circumstances. A
  malicious website could exploit this to conduct phishing attacks
  against the user. (CVE-2008-0594)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-576-1";
tag_affected = "firefox vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 6.10 ,
  Ubuntu 7.04 ,
  Ubuntu 7.10";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-February/000663.html");
  script_id(840192);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "576-1");
  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
  script_name( "Ubuntu Update for firefox vulnerabilities USN-576-1");

  script_description(desc);
  script_summary("Check for the Version of firefox vulnerabilities");
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

if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr-dev", ver:"1.firefox2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr4", ver:"1.firefox2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss-dev", ver:"1.firefox2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3", ver:"1.firefox2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr-dev", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr4", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss-dev", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr-dev", ver:"1.firefox2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr4", ver:"1.firefox2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss-dev", ver:"1.firefox2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3", ver:"1.firefox2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
