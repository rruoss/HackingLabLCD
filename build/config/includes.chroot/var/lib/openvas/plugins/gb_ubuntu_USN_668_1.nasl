###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for mozilla-thunderbird, thunderbird vulnerabilities USN-668-1
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
tag_insight = "Georgi Guninski, Michal Zalewsk and Chris Evans discovered that the same-origin
  check in Thunderbird could be bypassed. If a user were tricked into opening a
  malicious website, an attacker could obtain private information from data
  stored in the images, or discover information about software on the user's
  computer. (CVE-2008-5012)

  Jesse Ruderman discovered that Thunderbird did not properly guard locks on
  non-native objects. If a user had JavaScript enabled and were tricked into
  opening malicious web content, an attacker could cause a browser crash and
  possibly execute arbitrary code with user privileges. (CVE-2008-5014)
  
  Several problems were discovered in the browser, layout and JavaScript engines.
  If a user had JavaScript enabled, these problems could allow an attacker to
  crash Thunderbird and possibly execute arbitrary code with user privileges.
  (CVE-2008-5016, CVE-2008-5017, CVE-2008-5018)
  
  A flaw was discovered in Thunderbird's DOM constructing code. If a user were
  tricked into opening a malicious website while having JavaScript enabled, an
  attacker could cause the browser to crash and potentially execute arbitrary
  code with user privileges. (CVE-2008-5021)
  
  It was discovered that the same-origin check in Thunderbird could be bypassed.
  If a user had JavaScript enabled and were tricked into opening malicious web
  content, an attacker could execute JavaScript in the context of a different
  website. (CVE-2008-5022)
  
  Chris Evans discovered that Thunderbird did not properly parse E4X documents,
  leading to quote characters in the namespace not being properly escaped.
  (CVE-2008-5024)
  
  Boris Zbarsky discovered that Thunderbird did not properly process comments in
  forwarded in-line messages. If a user had JavaScript enabled and opened a
  malicious email, an attacker may be able to obtain information about the
  recipient.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-668-1";
tag_affected = "mozilla-thunderbird, thunderbird vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 7.10 ,
  Ubuntu 8.04 LTS ,
  Ubuntu 8.10";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-November/000788.html");
  script_id(840253);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "668-1");
  script_cve_id("CVE-2008-5012", "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5024");
  script_name( "Ubuntu Update for mozilla-thunderbird, thunderbird vulnerabilities USN-668-1");

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

if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.13+1.5.0.15~prepatch080614h-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.13+1.5.0.15~prepatch080614h-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.15~prepatch080614h-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15~prepatch080614h-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"2.0.0.18+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"2.0.0.18+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.18+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"2.0.0.18+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"2.0.0.18+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"2.0.0.18+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"2.0.0.18+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.18+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"2.0.0.18+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"2.0.0.18+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"2.0.0.18+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"2.0.0.18+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.18+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"2.0.0.18+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"2.0.0.18+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
