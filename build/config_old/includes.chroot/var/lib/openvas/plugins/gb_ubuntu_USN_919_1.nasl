###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for emacs22, emacs23 vulnerability USN-919-1
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
tag_insight = "Dan Rosenberg discovered that the email helper in Emacs did not correctly
  check file permissions.  A local attacker could perform a symlink race
  to read or append to another user's mailbox if it was stored under a
  group-writable group-&quot;mail&quot; directory.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-919-1";
tag_affected = "emacs22, emacs23 vulnerability on Ubuntu 8.04 LTS ,
  Ubuntu 8.10 ,
  Ubuntu 9.04 ,
  Ubuntu 9.10";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2010-March/001068.html");
  script_id(840409);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:56:44 +0200 (Tue, 06 Apr 2010)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "USN", value: "919-1");
  script_cve_id("CVE-2010-0825");
  script_name("Ubuntu Update for emacs22, emacs23 vulnerability USN-919-1");

  script_description(desc);
  script_summary("Check for the Version of emacs22, emacs23 vulnerability");
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

  if ((res = isdpkgvuln(pkg:"emacs22-bin-common", ver:"22.2-0ubuntu2.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-nox", ver:"22.2-0ubuntu2.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22", ver:"22.2-0ubuntu2.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-gtk", ver:"22.2-0ubuntu2.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-common", ver:"22.2-0ubuntu2.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-el", ver:"22.2-0ubuntu2.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs", ver:"22.2-0ubuntu2.9.04.1", rls:"UBUNTU9.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.10")
{

  if ((res = isdpkgvuln(pkg:"emacs22-bin-common", ver:"22.2-0ubuntu2.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-nox", ver:"22.2-0ubuntu2.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22", ver:"22.2-0ubuntu2.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-gtk", ver:"22.2-0ubuntu2.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-common", ver:"22.2-0ubuntu2.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-el", ver:"22.2-0ubuntu2.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs", ver:"22.2-0ubuntu2.8.10.1", rls:"UBUNTU8.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"emacs22-bin-common", ver:"22.1-0ubuntu10.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-nox", ver:"22.1-0ubuntu10.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22", ver:"22.1-0ubuntu10.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-gtk", ver:"22.1-0ubuntu10.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-common", ver:"22.1-0ubuntu10.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-el", ver:"22.1-0ubuntu10.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs", ver:"22.1-0ubuntu10.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"emacs22-bin-common", ver:"22.2-0ubuntu6.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-nox", ver:"22.2-0ubuntu6.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22", ver:"22.2-0ubuntu6.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-gtk", ver:"22.2-0ubuntu6.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs23-bin-common", ver:"23.1+1-4ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs23-lucid", ver:"23.1+1-4ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs23-nox", ver:"23.1+1-4ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs23", ver:"23.1+1-4ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-common", ver:"22.2-0ubuntu6.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs22-el", ver:"22.2-0ubuntu6.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs", ver:"23.1+1-4ubuntu2+22.2+0ubuntu6.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs23-common", ver:"23.1+1-4ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"emacs23-el", ver:"23.1+1-4ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
