###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for kernel SUSE-SA:2010:047
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "This update of the openSUSE 11.3 kernel fixes two local root exploits,
  various other security issues and some bugs.

  Following security issues are fixed by this update:
  CVE-2010-3301: Mismatch between 32bit and 64bit register usage in the
  system call entry path could be used by local attackers to gain root
  privileges. This problem only affects x86_64 kernels.

  CVE-2010-3081: Incorrect buffer handling in the biarch-compat buffer
  handling could be used by local attackers to gain root privileges. This
  problem affects foremost x86_64, or potentially other biarch platforms,
  like PowerPC and S390x.

  CVE-2010-3084: A buffer overflow in the ETHTOOL_GRXCLSRLALL code could
  be used to crash the kernel or potentially execute code.

  CVE-2010-2955: A kernel information leak via the WEXT ioctl was fixed.

  CVE-2010-2960: The keyctl_session_to_parent function in
  security/keys/keyctl.c in the Linux kernel expects that a certain parent
  session keyring exists, which allows local users to cause a denial of
  service (NULL pointer dereference and system crash) or possibly have
  unspecified other impact via a KEYCTL_SESSION_TO_PARENT argument to the
  keyctl function.

  CVE-2010-3080: A double free in an alsa error path was fixed, which could
  lead to kernel crashes.

  CVE-2010-3079: Fixed a ftrace NULL pointer dereference problem which
  could lead to kernel crashes.

  CVE-2010-3298: Fixed a kernel information leak in the net/usb/hso driver.

  CVE-2010-3296: Fixed a kernel information leak in the cxgb3 driver.

  CVE-2010-3297: Fixed a kernel information leak in the net/eql driver.";
tag_solution = "Please Install the Updated Packages.";

tag_impact = "local privilege escalation";
tag_affected = "kernel on openSUSE 11.3";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2010_47_kernel.html");
  script_id(850155);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-11 16:07:49 +0100 (Tue, 11 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "SUSE-SA", value: "2010-047");
  script_cve_id("CVE-2010-2955", "CVE-2010-2959", "CVE-2010-2960", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3081", "CVE-2010-3084", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3298", "CVE-2010-3301");
  script_name("SuSE Update for kernel SUSE-SA:2010:047");

  script_description(desc);
  script_summary("Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE11.3")
{

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop", rpm:"kernel-desktop~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-base", rpm:"kernel-desktop-base~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-devel", rpm:"kernel-desktop-devel~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vmi-base", rpm:"kernel-vmi-base~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vmi-devel", rpm:"kernel-vmi-devel~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.34.7~0.3.1", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"preload-kmp-default", rpm:"preload-kmp-default~1.1_k2.6.34.7_0.3~19.1.3", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"preload-kmp-desktop", rpm:"preload-kmp-desktop~1.1_k2.6.34.7_0.3~19.1.3", rls:"openSUSE11.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}