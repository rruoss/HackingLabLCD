###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for libxml2 vulnerability USN-569-1
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
tag_insight = "Brad Fitzpatrick discovered that libxml2 did not correctly handle certain
  UTF-8 sequences.  If a remote attacker were able to trick a user or
  automated system into processing a specially crafted XML document, the
  application linked against libxml2 could enter an infinite loop, leading
  to a denial of service via CPU resource consumption.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-569-1";
tag_affected = "libxml2 vulnerability on Ubuntu 6.06 LTS ,
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-January/000655.html");
  script_id(840241);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "USN", value: "569-1");
  script_cve_id("CVE-2007-6284");
  script_name( "Ubuntu Update for libxml2 vulnerability USN-569-1");

  script_description(desc);
  script_summary("Check for the Version of libxml2 vulnerability");
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

  if ((res = isdpkgvuln(pkg:"libxml2-dbg", ver:"2.6.27.dfsg-1ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.6.27.dfsg-1ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.6.27.dfsg-1ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2", ver:"2.6.27.dfsg-1ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-libxml2-dbg", ver:"2.6.27.dfsg-1ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-libxml2", ver:"2.6.27.dfsg-1ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-doc", ver:"2.6.27.dfsg-1ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxml2-dbg", ver:"2.6.24.dfsg-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.6.24.dfsg-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.6.24.dfsg-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2", ver:"2.6.24.dfsg-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python2.4-libxml2", ver:"2.6.24.dfsg-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-doc", ver:"2.6.24.dfsg-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-libxml2", ver:"2.6.24.dfsg-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"libxml2-dbg", ver:"2.6.26.dfsg-2ubuntu4.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.6.26.dfsg-2ubuntu4.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.6.26.dfsg-2ubuntu4.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2", ver:"2.6.26.dfsg-2ubuntu4.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-libxml2", ver:"2.6.26.dfsg-2ubuntu4.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-doc", ver:"2.6.26.dfsg-2ubuntu4.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"libxml2-dbg", ver:"2.6.30.dfsg-2ubuntu1.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.6.30.dfsg-2ubuntu1.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.6.30.dfsg-2ubuntu1.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2", ver:"2.6.30.dfsg-2ubuntu1.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-libxml2-dbg", ver:"2.6.30.dfsg-2ubuntu1.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-libxml2", ver:"2.6.30.dfsg-2ubuntu1.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxml2-doc", ver:"2.6.30.dfsg-2ubuntu1.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
