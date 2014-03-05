###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for mozilla-thunderbird, thunderbird vulnerabilities USN-536-1
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
tag_insight = "Various flaws were discovered in the layout and JavaScript engines. By
  tricking a user into opening a malicious web page, an attacker could
  execute arbitrary code with the user's privileges. (CVE-2007-5339,
  CVE-2007-5340)

  Flaws were discovered in the file upload form control. By tricking
  a user into opening a malicious web page, an attacker could force
  arbitrary files from the user's computer to be uploaded without their
  consent. (CVE-2006-2894, CVE-2007-3511)
  
  Michal Zalewski discovered that the onUnload event handlers were
  incorrectly able to access information outside the old page content. A
  malicious web site could exploit this to modify the contents, or
  steal confidential data (such as passwords), of the next loaded web
  page. (CVE-2007-1095)
  
  Stefano Di Paola discovered that Thunderbird did not correctly request
  Digest Authentications. A malicious web site could exploit this to
  inject arbitrary HTTP headers or perform session splitting attacks
  against proxies. (CVE-2007-2292)
  
  Eli Friedman discovered that XUL could be used to hide a window's
  titlebar. A malicious web site could exploit this to enhance their
  attempts at creating phishing web sites. (CVE-2007-5334)
  
  Georgi Guninski discovered that Thunderbird would allow file-system based
  web pages to access additional files. By tricking a user into opening
  a malicious web page from a gnome-vfs location, an attacker could steal
  arbitrary files from the user's computer. (CVE-2007-5337)
  
  It was discovered that the XPCNativeWrappers were not safe in
  certain situations. By tricking a user into opening a malicious web
  page, an attacker could run arbitrary JavaScript with the user's
  privileges. (CVE-2007-5338)
  
  Please note that JavaScript is disabled by default for emails, and it
  is not recommended to enable it.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-536-1";
tag_affected = "mozilla-thunderbird, thunderbird vulnerabilities on Ubuntu 6.06 LTS ,
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2007-October/000615.html");
  script_id(840060);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "536-1");
  script_cve_id("CVE-2006-2894", "CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
  script_name( "Ubuntu Update for mozilla-thunderbird, thunderbird vulnerabilities USN-536-1");

  script_description(desc);
  script_summary("Check for the Version of mozilla-thunderbird, thunderbird vulnerabilities");
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

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.7.04", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.7.04", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.7.04", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.7.04", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.06", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.10", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"2.0.0.8~pre071022+nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"2.0.0.8~pre071022+nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.8~pre071022+nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"2.0.0.8~pre071022+nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"2.0.0.8~pre071022+nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
