###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-1473-1
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
tag_insight = "A flaw was discovered in the Linux kernel's KVM (kernel virtual machine).
  An administrative user in the guest OS could leverage this flaw to cause a
  denial of service in the host OS. (CVE-2012-2121)

  Schacher Raindel discovered a flaw in the Linux kernel's memory handling
  when hugetlb is enabled. An unprivileged local attacker could exploit this
  flaw to cause a denial of service and potentially gain higher privileges.
  (CVE-2012-2133)

  Stephan Mueller reported a flaw in the Linux kernel's dl2k network driver's
  handling of ioctls. An unprivileged local user could leverage this flaw to
  cause a denial of service. (CVE-2012-2313)

  Timo Warns reported multiple flaws in the Linux kernel's hfsplus
  filesystem. An unprivileged local user could exploit these flaws to gain
  root system priviliges. (CVE-2012-2319)

  Xi Wang discovered a flaw in the Linux kernel's i915 graphics driver
  handling of cliprect on 32 bit systems. An unprivileged local attacker
  could leverage this flaw to cause a denial of service or potentially gain
  root privileges. (CVE-2012-2383)

  Xi Wang discovered a flaw in the Linux kernel's i915 graphics driver
  handling of buffer_count on 32 bit systems. An unprivileged local attacker
  could leverage this flaw to cause a denial of service or potentially gain
  root privileges. (CVE-2012-2384)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1473-1";
tag_affected = "linux on Ubuntu 12.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-June/001719.html");
  script_id(841044);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-15 09:47:16 +0530 (Fri, 15 Jun 2012)");
  script_cve_id("CVE-2012-2121", "CVE-2012-2133", "CVE-2012-2313", "CVE-2012-2319",
                "CVE-2012-2383", "CVE-2012-2384");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1473-1");
  script_name("Ubuntu Update for linux USN-1473-1");

  script_description(desc);
  script_summary("Check for the Version of linux");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-25-generic", ver:"3.2.0-25.40", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-25-generic-pae", ver:"3.2.0-25.40", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-25-highbank", ver:"3.2.0-25.40", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-25-omap", ver:"3.2.0-25.40", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-25-powerpc-smp", ver:"3.2.0-25.40", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-25-powerpc64-smp", ver:"3.2.0-25.40", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-25-virtual", ver:"3.2.0-25.40", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
