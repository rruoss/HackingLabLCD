###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for eglibc USN-1396-1
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
tag_insight = "It was discovered that the GNU C Library did not properly handle
  integer overflows in the timezone handling code. An attacker could use
  this to possibly execute arbitrary code by convincing an application
  to load a maliciously constructed tzfile. (CVE-2009-5029)

  It was discovered that the GNU C Library did not properly handle
  passwd.adjunct.byname map entries in the Network Information Service
  (NIS) code in the name service caching daemon (nscd). An attacker
  could use this to obtain the encrypted passwords of NIS accounts.
  This issue only affected Ubuntu 8.04 LTS. (CVE-2010-0015)

  Chris Evans reported that the GNU C Library did not properly
  calculate the amount of memory to allocate in the fnmatch() code. An
  attacker could use this to cause a denial of service or possibly
  execute arbitrary code via a maliciously crafted UTF-8 string.
  This issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS and Ubuntu
  10.10. (CVE-2011-1071)

  Tomas Hoger reported that an additional integer overflow was possible
  in the GNU C Library fnmatch() code. An attacker could use this to
  cause a denial of service via a maliciously crafted UTF-8 string. This
  issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10
  and Ubuntu 11.04. (CVE-2011-1659)

  Dan Rosenberg discovered that the addmntent() function in the GNU C
  Library did not report an error status for failed attempts to write to
  the /etc/mtab file. This could allow an attacker to corrupt /etc/mtab,
  possibly causing a denial of service or otherwise manipulate mount
  options. This issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS,
  Ubuntu 10.10 and Ubuntu 11.04. (CVE-2011-1089)

  Harald van Dijk discovered that the locale program included with the
  GNU C library did not properly quote its output. This could allow a
  local attacker to possibly execute arbitrary code using a crafted
  localization string that was evaluated in a shell script. This
  issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS and Ubuntu
  10.10. (CVE-2011-1095)

  It was discovered that the GNU C library loader expanded the
  $ORIGIN dynamic string token when RPATH is composed entirely of this
  token. This could allow an attacker to gain privilege via a setuid
  program that had this RPATH value. (CVE-2011-1658)

  It was discovered that the GNU C library implementation of memcpy
  optimized for Supplemental Streaming SIMD Extensions 3 (SSSE3)
  contained a possible integer overflow. An attacker could use this to
  cause a denial of service or possibly exec ...

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1396-1";
tag_affected = "eglibc on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-March/001626.html");
  script_id(840929);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-12 12:42:00 +0530 (Mon, 12 Mar 2012)");
  script_cve_id("CVE-2009-5029", "CVE-2010-0015", "CVE-2011-1071", "CVE-2011-1659",
                "CVE-2011-1089", "CVE-2011-1095", "CVE-2011-1658", "CVE-2011-2702",
                "CVE-2011-4609", "CVE-2012-0864");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1396-1");
  script_name("Ubuntu Update for eglibc USN-1396-1");

  script_description(desc);
  script_summary("Check for the Version of eglibc");
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"libc-bin", ver:"2.12.1-0ubuntu10.4", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.12.1-0ubuntu10.4", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libc-bin", ver:"2.11.1-0ubuntu7.10", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.11.1-0ubuntu7.10", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.13-0ubuntu13.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.7-10ubuntu8.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
