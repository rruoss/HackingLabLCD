###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-1805-1
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
tag_insight = "Mathias Krause discovered an information leak in the Linux kernel's
  getsockname implementation for Logical Link Layer (llc) sockets. A local
  user could exploit this flaw to examine some of the kernel's stack memory.
  (CVE-2012-6542)

  Mathias Krause discovered information leaks in the Linux kernel's Bluetooth
  Logical Link Control and Adaptation Protocol (L2CAP) implementation. A
  local user could exploit these flaws to examine some of the kernel's stack
  memory. (CVE-2012-6544)

  Mathias Krause discovered information leaks in the Linux kernel's Bluetooth
  RFCOMM protocol implementation. A local user could exploit these flaws to
  examine parts of kernel memory. (CVE-2012-6545)

  Mathias Krause discovered information leaks in the Linux kernel's
  Asynchronous Transfer Mode (ATM) networking stack. A local user could
  exploit these flaws to examine some parts of kernel memory. (CVE-2012-6546)

  Mathias Krause discovered an information leak in the Linux kernel's UDF
  file system implementation. A local user could exploit this flaw to examine
  some of the kernel's heap memory. (CVE-2012-6548)

  Andrew Jones discovered a flaw with the xen_iret function in Linux kernel's
  Xen virtualizeation. In the 32-bit Xen paravirt platform an unprivileged
  guest OS user could exploit this flaw to cause a denial of service (crash
  the system) or gain guest OS privilege. (CVE-2013-0228)

  An information leak was discovered in the Linux kernel's Bluetooth stack
  when HIDP (Human Interface Device Protocol) support is enabled. A local
  unprivileged user could exploit this flaw to cause an information leak from
  the kernel. (CVE-2013-0349)

  A flaw was discovered in the Edgeort USB serial converter driver when the
  device is disconnected while it is in use. A local user could exploit this
  flaw to cause a denial of service (system crash). (CVE-2013-1774)

  Andrew Honig discovered a flaw in guest OS time updates in the Linux
  kernel's KVM (Kernel-based Virtual Machine). A privileged guest user could
  exploit this flaw to cause a denial of service (crash host system) or
  potential escalate privilege to the host kernel level. (CVE-2013-1796)";


tag_solution = "Please Install the Updated Packages.";
tag_affected = "linux on Ubuntu 10.04 LTS";

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
  script_id(841404);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-22 10:33:11 +0530 (Mon, 22 Apr 2013)");
  script_cve_id("CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546",
                "CVE-2012-6548", "CVE-2013-0228", "CVE-2013-0349", "CVE-2013-1774",
                "CVE-2013-1796");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ubuntu Update for linux USN-1805-1");

  script_description(desc);
  script_xref(name: "USN", value: "1805-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-April/002086.html");
  script_summary("Check for the Version of linux");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-386", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-generic", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-generic-pae", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-ia64", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-lpia", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-powerpc", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-powerpc-smp", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-powerpc64-smp", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-preempt", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-server", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-sparc64", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-sparc64-smp", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-versatile", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-46-virtual", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
