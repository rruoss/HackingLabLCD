###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for glibc USN-1589-2
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
tag_insight = "USN-1589-1 fixed vulnerabilities in the GNU C Library. One of the updates
  exposed a regression in the floating point parser. This update fixes the
  problem.

  We apologize for the inconvenience.
  
  Original advisory details:
  
  It was discovered that positional arguments to the printf() family
  of functions were not handled properly in the GNU C Library. An
  attacker could possibly use this to cause a stack-based buffer
  overflow, creating a denial of service or possibly execute arbitrary
  code. (CVE-2012-3404, CVE-2012-3405, CVE-2012-3406)
  It was discovered that multiple integer overflows existed in the
  strtod(), strtof() and strtold() functions in the GNU C Library. An
  attacker could possibly use this to trigger a stack-based buffer
  overflow, creating a denial of service or possibly execute arbitrary
  code. (CVE-2012-3480)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1589-2";
tag_affected = "glibc on Ubuntu 8.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-December/001933.html");
  script_id(841254);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-18 10:04:54 +0530 (Tue, 18 Dec 2012)");
  script_cve_id("CVE-2012-3404", "CVE-2012-3405", "CVE-2012-3406", "CVE-2012-3480");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "USN", value: "1589-2");
  script_name("Ubuntu Update for glibc USN-1589-2");

  script_description(desc);
  script_summary("Check for the Version of glibc");
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

if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libc6", ver:"2.7-10ubuntu8.3", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
