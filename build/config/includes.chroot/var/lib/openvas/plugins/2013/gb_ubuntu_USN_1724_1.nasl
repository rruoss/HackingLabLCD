###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openjdk-7 USN-1724-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Several vulnerabilities were discovered in the OpenJDK JRE related to
  information disclosure and data integrity. An attacker could exploit these
  to cause a denial of service. (CVE-2012-1541, CVE-2012-3342, CVE-2013-0351,
  CVE-2013-0419, CVE-2013-0423, CVE-2013-0446, CVE-2012-3213, CVE-2013-0425,
  CVE-2013-0426, CVE-2013-0428, CVE-2013-0429, CVE-2013-0430, CVE-2013-0441,
  CVE-2013-0442, CVE-2013-0445, CVE-2013-0450, CVE-2013-1475, CVE-2013-1476,
  CVE-2013-1478, CVE-2013-1480)

  Vulnerabilities were discovered in the OpenJDK JRE related to information
  disclosure. (CVE-2013-0409, CVE-2013-0434, CVE-2013-0438)
  
  Several data integrity vulnerabilities were discovered in the OpenJDK JRE.
  (CVE-2013-0424, CVE-2013-0427, CVE-2013-0433, CVE-2013-1473)
  
  Several vulnerabilities were discovered in the OpenJDK JRE related to
  information disclosure and data integrity. (CVE-2013-0432, CVE-2013-0435,
  CVE-2013-0443)
  
  A vulnerability was discovered in the OpenJDK JRE related to availability.
  An attacker could exploit this to cause a denial of service.
  (CVE-2013-0440)
  
  A vulnerability was discovered in the OpenJDK JRE related to information
  disclosure and data integrity. An attacker could exploit this to cause a
  denial of service. This issue only affected Ubuntu 12.10. (CVE-2013-0444)
  
  A data integrity vulnerability was discovered in the OpenJDK JRE. This
  issue only affected Ubuntu 12.10. (CVE-2013-0448)
  
  An information disclosure vulnerability was discovered in the OpenJDK JRE.
  This issue only affected Ubuntu 12.10. (CVE-2013-0449)
  
  A vulnerability was discovered in the OpenJDK JRE related to information
  disclosure and data integrity. An attacker could exploit this to cause a
  denial of service. This issue did not affect Ubuntu 12.10. (CVE-2013-1481)";


tag_solution = "Please Install the Updated Packages.";
tag_affected = "openjdk-7 on Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 11.10 ,
  Ubuntu 10.04 LTS";

  desc = "

    Vulnerability Insight:
    " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;



if(description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "insight" , value : tag_insight);
  }
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-February/001996.html");
  script_id(841310);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-15 11:22:47 +0530 (Fri, 15 Feb 2013)");
  script_cve_id("CVE-2012-1541", "CVE-2012-3342", "CVE-2013-0351", "CVE-2013-0419",
                "CVE-2013-0423", "CVE-2013-0446", "CVE-2012-3213", "CVE-2013-0425",
                "CVE-2013-0426", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0430",
                "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0445", "CVE-2013-0450",
                "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480",
                "CVE-2013-0409", "CVE-2013-0434", "CVE-2013-0438", "CVE-2013-0424",
                "CVE-2013-0427", "CVE-2013-0433", "CVE-2013-1473", "CVE-2013-0432",
                "CVE-2013-0435", "CVE-2013-0443", "CVE-2013-0440", "CVE-2013-0444",
                "CVE-2013-0448", "CVE-2013-0449", "CVE-2013-1481");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1724-1");
  script_name("Ubuntu Update for openjdk-7 USN-1724-1");

  script_description(desc);
  script_summary("Check for the Version of openjdk-7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b27-1.12.1-2ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b27-1.12.1-2ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b27-1.12.1-2ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b27-1.12.1-2ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b27-1.12.1-2ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u13-2.3.6-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u13-2.3.6-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u13-2.3.6-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u13-2.3.6-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u13-2.3.6-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
