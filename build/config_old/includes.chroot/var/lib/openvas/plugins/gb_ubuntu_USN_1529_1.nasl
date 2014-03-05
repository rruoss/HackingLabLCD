###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-1529-1
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
tag_insight = "A flaw was discovered in the Linux kernel's macvtap device driver, which is
  used in KVM (Kernel-based Virtual Machine) to create a network bridge
  between host and guest. A privleged user in a guest could exploit this flaw
  to crash the host, if the vhost_net module is loaded with the
  experimental_zcopytx option enabled. (CVE-2012-2119)

  An error was discovered in the Linux kernel's network TUN/TAP device
  implementation. A local user with access to the TUN/TAP interface (which is
  not available to unprivileged users until granted by a root user) could
  exploit this flaw to crash the system or potential gain administrative
  privileges. (CVE-2012-2136)
  
  A flaw was found in how the Linux kernel's KVM (Kernel-based Virtual
  Machine) subsystem handled MSI (Message Signaled Interrupts). A local
  unprivileged user could exploit this flaw to cause a denial of service or
  potentially elevate privileges. (CVE-2012-2137)
  
  A flaw was found in the Linux kernel's Reliable Datagram Sockets (RDS)
  protocol implementation. A local, unprivileged user could use this flaw to
  cause a denial of service. (CVE-2012-2372)
  
  Ulrich Obergfell discovered an error in the Linux kernel's memory
  management subsystem on 32 bit PAE systems with more than 4GB of memory
  installed. A local unprivileged user could exploit this flaw to crash the
  system. (CVE-2012-2373)
  
  Dan Rosenberg discovered flaws in the Linux kernel's NCI (Near Field
  Communication Controller Interface). A remote attacker could exploit these
  flaws to crash the system or potentially execute privileged code.
  (CVE-2012-3364)
  
  A flaw was discovered in the Linux kernel's epoll system call. An
  unprivileged local user could use this flaw to crash the system.
  (CVE-2012-3375)
  
  Some errors where discovered in the Linux kernel's UDF file system, which
  is used to mount some CD-ROMs and DVDs. An unprivileged local user could
  use these flaws to crash the system. (CVE-2012-3400)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1529-1";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-August/001782.html");
  script_id(841104);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-14 10:40:22 +0530 (Tue, 14 Aug 2012)");
  script_cve_id("CVE-2012-2119", "CVE-2012-2136", "CVE-2012-2137", "CVE-2012-2372",
                "CVE-2012-2373", "CVE-2012-3364", "CVE-2012-3375", "CVE-2012-3400");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1529-1");
  script_name("Ubuntu Update for linux USN-1529-1");

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

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-29-generic", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-29-generic-pae", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-29-highbank", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-29-omap", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-29-powerpc-smp", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-29-powerpc64-smp", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-29-virtual", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
