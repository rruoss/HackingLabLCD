###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for icedtea-web USN-1804-2
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
tag_insight = "USN-1804-1 fixed vulnerabilities in IcedTea-Web. This update introduced
  a regression with the Java Network Launching Protocol (JNLP) when fetching
  content over SSL under certain configurations, such as when using the
  community-supported IcedTead 7 browser plugin. This update fixes the
  problem.

  We apologize for the inconvenience.

  Original advisory details:

  Jiri Vanek discovered that IcedTea-Web would use the same classloader for
  applets from different domains. A remote attacker could exploit this to
  expose sensitive information or potentially manipulate applets from other
  domains. (CVE-2013-1926)

  It was discovered that IcedTea-Web did not properly verify JAR files and
  was susceptible to the GIFAR attack. If a user were tricked into opening a
  malicious website, a remote attacker could potentially exploit this to
  execute code under certain circumstances. (CVE-2013-1927)";


tag_solution = "Please Install the Updated Packages.";
tag_affected = "icedtea-web on Ubuntu 12.04 LTS ,
  Ubuntu 11.10";

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
  script_id(841407);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-25 10:49:59 +0530 (Thu, 25 Apr 2013)");
  script_cve_id("CVE-2013-1926", "CVE-2013-1927");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ubuntu Update for icedtea-web USN-1804-2");

  script_description(desc);
  script_xref(name: "USN", value: "1804-2");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-April/002088.html");
  script_summary("Check for the Version of icedtea-web");
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

  if ((res = isdpkgvuln(pkg:"icedtea-7-plugin", ver:"1.2.3-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.2.3-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"icedtea-netx", ver:"1.2.3-0ubuntu0.11.10.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
