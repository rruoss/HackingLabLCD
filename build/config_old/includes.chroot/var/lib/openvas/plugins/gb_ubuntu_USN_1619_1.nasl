###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openjdk-7 USN-1619-1
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
tag_insight = "Several information disclosure vulnerabilities were discovered in the
  OpenJDK JRE. (CVE-2012-3216, CVE-2012-5069, CVE-2012-5072, CVE-2012-5075,
  CVE-2012-5077, CVE-2012-5085)

  Vulnerabilities were discovered in the OpenJDK JRE related to information
  disclosure and data integrity. (CVE-2012-4416, CVE-2012-5071)
  
  Several vulnerabilities were discovered in the OpenJDK JRE related to
  information disclosure and data integrity. An attacker could exploit these
  to cause a denial of service. (CVE-2012-1531, CVE-2012-1532, CVE-2012-1533,
  CVE-2012-3143, CVE-2012-3159, CVE-2012-5068, CVE-2012-5083, CVE-2012-5084,
  CVE-2012-5086, CVE-2012-5089)
  
  Information disclosure vulnerabilities were discovered in the OpenJDK JRE.
  These issues only affected Ubuntu 12.10. (CVE-2012-5067, CVE-2012-5070)
  
  Vulnerabilities were discovered in the OpenJDK JRE related to data
  integrity. (CVE-2012-5073, CVE-2012-5079)
  
  A vulnerability was discovered in the OpenJDK JRE related to information
  disclosure and data integrity. This issue only affected Ubuntu 12.10.
  (CVE-2012-5074)
  
  Several vulnerabilities were discovered in the OpenJDK JRE related to
  information disclosure and data integrity. An attacker could exploit these
  to cause a denial of service. These issues only affected Ubuntu 12.10.
  (CVE-2012-5076, CVE-2012-5087, CVE-2012-5088)
  
  A denial of service vulnerability was found in OpenJDK. (CVE-2012-5081)
  
  Please see the following for more information:
  http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1619-1";
tag_affected = "openjdk-7 on Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 11.04 ,
  Ubuntu 10.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-October/001880.html");
  script_id(841202);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-29 11:03:54 +0530 (Mon, 29 Oct 2012)");
  script_cve_id("CVE-2012-3216", "CVE-2012-5069", "CVE-2012-5072", "CVE-2012-5075",
                "CVE-2012-5077", "CVE-2012-5085", "CVE-2012-4416", "CVE-2012-5071",
                "CVE-2012-1531", "CVE-2012-1532", "CVE-2012-1533", "CVE-2012-3143",
                "CVE-2012-3159", "CVE-2012-5068", "CVE-2012-5083", "CVE-2012-5084",
                "CVE-2012-5086", "CVE-2012-5089", "CVE-2012-5067", "CVE-2012-5070",
                "CVE-2012-5073", "CVE-2012-5079", "CVE-2012-5074", "CVE-2012-5076",
                "CVE-2012-5087", "CVE-2012-5088", "CVE-2012-5081");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1619-1");
  script_name("Ubuntu Update for openjdk-7 USN-1619-1");

  script_description(desc);
  script_summary("Check for the Version of openjdk-7");
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

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b24-1.11.5-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b24-1.11.5-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b24-1.11.5-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b24-1.11.5-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b24-1.11.5-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b24-1.11.5-0ubuntu1~12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b24-1.11.5-0ubuntu1~11.10.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b24-1.11.5-0ubuntu1~11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
