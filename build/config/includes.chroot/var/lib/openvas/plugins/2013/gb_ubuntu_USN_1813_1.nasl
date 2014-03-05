###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-1813-1
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
tag_insight = "Mathias Krause discovered an information leak in the Linux kernel's UDF
  file system implementation. A local user could exploit this flaw to examine
  some of the kernel's heap memory. (CVE-2012-6548)

  Mathias Krause discovered an information leak in the Linux kernel's ISO
  9660 CDROM file system driver. A local user could exploit this flaw to
  examine some of the kernel's heap memory. (CVE-2012-6549)

  An integer overflow was discovered in the Direct Rendering Manager (DRM)
  subsystem for the i915 video driver in the Linux kernel. A local user could
  exploit this flaw to cause a denial of service (crash) or potentially
  escalate privileges. (CVE-2013-0913)

  Andrew Honig discovered a flaw in guest OS time updates in the Linux
  kernel's KVM (Kernel-based Virtual Machine). A privileged guest user could
  exploit this flaw to cause a denial of service (crash host system) or
  potential escalate privilege to the host kernel level. (CVE-2013-1796)

  Andrew Honig discovered a use after free error in guest OS time updates in
  the Linux kernel;s KVM (Kernel-based Virtual Machine). A privileged guest
  user could exploit this flaw to escalate privilege to the host kernel
  level. (CVE-2013-1797)

  Andrew Honig reported a flaw in the way KVM (Kernel-based Virtual Machine)
  emulated the IOAPIC. A privileged guest user could exploit this flaw to
  read host memory or cause a denial of service (crash the host).
  (CVE-2013-1798)

  A format-string bug was discovered in the Linux kernel's ext3 filesystem
  driver. A local user could exploit this flaw to possibly escalate
  privileges on the system. (CVE-2013-1848)

  A buffer overflow was discovered in the Linux Kernel's USB subsystem for
  devices reporting the cdc-wdm class. A specially crafted USB device when
  plugged-in could cause a denial of service (system crash) or possibly
  execute arbitrary code. (CVE-2013-1860)

  An information leak in the Linux kernel's dcb netlink interface was
  discovered. A local user could obtain sensitive information by examining
  kernel stack memory. (CVE-2013-2634)

  A kernel stack information leak was discovered in the RTNETLINK component
  of the Linux kernel. A local user could read sensitive information from the
  kernel stack. (CVE-2013-2635)";


tag_affected = "linux on Ubuntu 12.10";
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
  script_id(841414);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-14 12:54:04 +0530 (Fri, 14 Jun 2013)");
  script_cve_id("CVE-2012-6548", "CVE-2012-6549", "CVE-2013-0913", "CVE-2013-1796",
                "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1848", "CVE-2013-1860",
                "CVE-2013-2634", "CVE-2013-2635");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ubuntu Update for linux USN-1813-1");

  script_description(desc);
  script_xref(name: "USN", value: "1813-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-May/002095.html");
  script_summary("Check for the Version of linux");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-28-generic", ver:"3.5.0-28.48", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-28-highbank", ver:"3.5.0-28.48", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-28-omap", ver:"3.5.0-28.48", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-28-powerpc-smp", ver:"3.5.0-28.48", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-28-powerpc64-smp", ver:"3.5.0-28.48", rls:"UBUNTU12.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
