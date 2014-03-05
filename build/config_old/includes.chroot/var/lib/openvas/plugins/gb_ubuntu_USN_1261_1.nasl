###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for quagga USN-1261-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Riku Hietam&#228;ki, Tuomo Untinen and Jukka Taimisto discovered that Quagga
  incorrectly handled Link State Update messages with invalid lengths. A
  remote attacker could use this flaw to cause Quagga to crash, resulting in
  a denial of service. (CVE-2011-3323)

  Riku Hietam&#228;ki, Tuomo Untinen and Jukka Taimisto discovered that Quagga
  incorrectly handled certain IPv6 Database Description messages. A remote
  attacker could use this flaw to cause Quagga to crash, resulting in a
  denial of service. (CVE-2011-3324)

  Riku Hietam&#228;ki, Tuomo Untinen and Jukka Taimisto discovered that Quagga
  incorrectly handled certain IPv4 packets. A remote attacker could use this
  flaw to cause Quagga to crash, resulting in a denial of service.
  (CVE-2011-3325)

  Riku Hietam&#228;ki, Tuomo Untinen and Jukka Taimisto discovered that Quagga
  incorrectly handled invalid Link State Advertisement (LSA) types. A remote
  attacker could use this flaw to cause Quagga to crash, resulting in a
  denial of service. (CVE-2011-3326)

  Riku Hietam&#228;ki, Tuomo Untinen and Jukka Taimisto discovered that Quagga
  incorrectly handled certain BGP UPDATE messages. A remote attacker could
  use this flaw to cause Quagga to crash, or possibly execute arbitrary
  code. (CVE-2011-3327)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1261-1";
tag_affected = "quagga on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
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
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-November/001479.html");
  script_id(840806);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-18 09:47:01 +0530 (Fri, 18 Nov 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1261-1");
  script_cve_id("CVE-2011-3323", "CVE-2011-3324", "CVE-2011-3325", "CVE-2011-3326", "CVE-2011-3327");
  script_name("Ubuntu Update for quagga USN-1261-1");

  script_description(desc);
  script_summary("Check for the Version of quagga");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"quagga", ver:"0.99.17-1ubuntu0.2", rls:"UBUNTU10.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"quagga", ver:"0.99.15-1ubuntu0.3", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"quagga", ver:"0.99.17-4ubuntu1.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
