###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openjdk-7 USN-1806-1
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
tag_insight = "Ben Murphy discovered a vulnerability in the OpenJDK JRE related to
  information disclosure and data integrity. An attacker could exploit this
  to execute arbitrary code. (CVE-2013-0401)

  James Forshaw discovered a vulnerability in the OpenJDK JRE related to
  information disclosure, data integrity and availability. An attacker could
  exploit this to execute arbitrary code. (CVE-2013-1488)
  
  Several vulnerabilities were discovered in the OpenJDK JRE related to
  information disclosure, data integrity and availability. An attacker could
  exploit these to cause a denial of service or expose sensitive data over
  the network. (CVE-2013-1518, CVE-2013-1537, CVE-2013-1557, CVE-2013-1569,
  CVE-2013-2383, CVE-2013-2384, CVE-2013-2420, CVE-2013-2421, CVE-2013-2422,
  CVE-2013-2426, CVE-2013-2429, CVE-2013-2430, CVE-2013-2431, CVE-2013-2436)
  
  Two vulnerabilities were discovered in the OpenJDK JRE related to
  confidentiality. An attacker could exploit these to expose sensitive data
  over the network. (CVE-2013-2415, CVE-2013-2424)
  
  Two vulnerabilities were discovered in the OpenJDK JRE related to
  availability. An attacker could exploit these to cause a denial of service.
  (CVE-2013-2417, CVE-2013-2419)
  
  A vulnerability was discovered in the OpenJDK JRE related to data
  integrity. (CVE-2013-2423)";


tag_affected = "openjdk-7 on Ubuntu 12.10";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
if(description)
{
  script_id(841405);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-25 10:46:38 +0530 (Thu, 25 Apr 2013)");
  script_cve_id("CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1518", "CVE-2013-1537",
                "CVE-2013-1557", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384",
                "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2426",
                "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431", "CVE-2013-2436",
                "CVE-2013-2415", "CVE-2013-2424", "CVE-2013-2417", "CVE-2013-2419",
                "CVE-2013-2423", "CVE-2013-1558");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Ubuntu Update for openjdk-7 USN-1806-1");

  script_description(desc);
  script_xref(name: "USN", value: "1806-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-April/002087.html");
  script_summary("Check for the Version of openjdk-7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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

if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u21-2.3.9-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u21-2.3.9-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u21-2.3.9-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u21-2.3.9-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u21-2.3.9-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
