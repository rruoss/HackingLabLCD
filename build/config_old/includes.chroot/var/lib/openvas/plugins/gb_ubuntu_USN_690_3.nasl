###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox vulnerabilities USN-690-3
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
tag_insight = "Several flaws were discovered in the browser engine. These problems could allow
  an attacker to crash the browser and possibly execute arbitrary code with user
  privileges. (CVE-2008-5500)

  Boris Zbarsky discovered that the same-origin check in Firefox could be
  bypassed by utilizing XBL-bindings. An attacker could exploit this to read data
  from other domains. (CVE-2008-5503)
  
  Marius Schilder discovered that Firefox did not properly handle redirects to
  an outside domain when an XMLHttpRequest was made to a same-origin resource.
  It's possible that sensitive information could be revealed in the
  XMLHttpRequest response. (CVE-2008-5506)
  
  Chris Evans discovered that Firefox did not properly protect a user's data when
  accessing a same-domain Javascript URL that is redirected to an unparsable
  Javascript off-site resource. If a user were tricked into opening a malicious
  website, an attacker may be able to steal a limited amount of private data.
  (CVE-2008-5507)
  
  Several flaws were discovered in the Javascript engine. If a user were tricked
  into opening a malicious website, an attacker could exploit this to execute
  arbitrary Javascript code within the context of another website or with chrome
  privileges. (CVE-2008-5511, CVE-2008-5512)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-690-3";
tag_affected = "firefox vulnerabilities on Ubuntu 6.06 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-December/000807.html");
  script_id(840233);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "690-3");
  script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5511", "CVE-2008-5512");
  script_name( "Ubuntu Update for firefox vulnerabilities USN-690-3");

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

if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox-dbg", ver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr-dev", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnspr4", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss-dev", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libnss3", ver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"mozilla-firefox-dev", ver:"1.5.dfsg+1.5.0.15~prepatch080614i-0ubuntu1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
