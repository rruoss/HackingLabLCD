###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for libexif USN-1513-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Mateusz Jurczyk discovered that libexif incorrectly parsed certain
  malformed EXIF tags. If a user or automated system were tricked into
  processing a specially crafted image file, an attacker could cause libexif
  to crash, leading to a denial of service, or possibly obtain sensitive
  information. (CVE-2012-2812, CVE-2012-2813)

  Mateusz Jurczyk discovered that libexif incorrectly parsed certain
  malformed EXIF tags. If a user or automated system were tricked into
  processing a specially crafted image file, an attacker could cause libexif
  to crash, leading to a denial of service, or possibly execute arbitrary
  code. (CVE-2012-2814)

  Yunho Kim discovered that libexif incorrectly parsed certain malformed EXIF
  tags. If a user or automated system were tricked into processing a
  specially crafted image file, an attacker could cause libexif to crash,
  leading to a denial of service, or possibly obtain sensitive information.
  (CVE-2012-2836)

  Yunho Kim discovered that libexif incorrectly parsed certain malformed EXIF
  tags. If a user or automated system were tricked into processing a
  specially crafted image file, an attacker could cause libexif to crash,
  leading to a denial of service. (CVE-2012-2837)

  Dan Fandrich discovered that libexif incorrectly parsed certain malformed
  EXIF tags. If a user or automated system were tricked into processing a
  specially crafted image file, an attacker could cause libexif to crash,
  leading to a denial of service, or possibly execute arbitrary code.
  (CVE-2012-2840, CVE-2012-2841)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1513-1";
tag_affected = "libexif on Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 11.04 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 8.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-July/001767.html");
  script_id(841092);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-26 11:10:08 +0530 (Thu, 26 Jul 2012)");
  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836",
                "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1513-1");
  script_name("Ubuntu Update for libexif USN-1513-1");

  script_description(desc);
  script_summary("Check for the Version of libexif");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.19-1ubuntu0.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.20-2ubuntu0.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.20-1ubuntu0.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.20-0ubuntu1.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.16-2.1ubuntu0.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
