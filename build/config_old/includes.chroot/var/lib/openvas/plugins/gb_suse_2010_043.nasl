###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for kernel SUSE-SA:2010:043
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
tag_insight = "The SUSE Linux Enterprise 11 GA and openSUSE 11.1 kernels were updated
  to fix 3 critical security issues.

  Following security bugs were fixed:
  CVE-2010-3301: Mismatch between 32bit and 64bit register usage in the
  system call entry paths could be used by local attackers to gain root
  privileges. This problem only affects x86_64 kernels.

  CVE-2010-3081: Incorrect buffer handling in the biarch-compat buffer
  handling could be used by local attackers to gain root privileges. This
  problem affects foremost x86_64 where a exploit exists, and potentially
  other biarch platforms, like PowerPC and S/390.

  CVE-2010-2959: Integer overflow in net/can/bcm.c in the Controller
  Area Network (CAN) implementation in the Linux kernel allowed attackers
  to execute arbitrary code or cause a denial of service (system crash)
  via crafted CAN traffic.

  No other bugs were fixed in this update.";
tag_solution = "Please Install the Updated Packages.";

tag_impact = "local privilege escalation";
tag_affected = "kernel on openSUSE 11.1";

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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2010_43_kernel.html");
  script_id(850142);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-01 08:16:52 +0200 (Fri, 01 Oct 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "SUSE-SA", value: "2010-043");
  script_cve_id("CVE-2010-2959", "CVE-2010-3081", "CVE-2010-3301");
  script_name("SuSE Update for kernel SUSE-SA:2010:043");

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

if(release == "openSUSE11.1")
{

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-extra", rpm:"kernel-debug-extra~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~2.6.27.48~0.3.1", rls:"openSUSE11.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
