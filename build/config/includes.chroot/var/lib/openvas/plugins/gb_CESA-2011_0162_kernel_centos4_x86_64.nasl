###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2011:0162 centos4 x86_64
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
tag_insight = "The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:
  
  * A heap overflow flaw was found in the Linux kernel's Transparent
  Inter-Process Communication protocol (TIPC) implementation. A local,
  unprivileged user could use this flaw to escalate their privileges.
  (CVE-2010-3859, Important)
  
  * Missing sanity checks were found in gdth_ioctl_alloc() in the gdth driver
  in the Linux kernel. A local user with access to &quot;/dev/gdth&quot; on a 64-bit
  system could use these flaws to cause a denial of service or escalate their
  privileges. (CVE-2010-4157, Moderate)
  
  * A NULL pointer dereference flaw was found in the Bluetooth HCI UART
  driver in the Linux kernel. A local, unprivileged user could use this flaw
  to cause a denial of service. (CVE-2010-4242, Moderate)
  
  * A flaw was found in the Linux kernel's garbage collector for AF_UNIX
  sockets. A local, unprivileged user could use this flaw to trigger a
  denial of service (out-of-memory condition). (CVE-2010-4249, Moderate)
  
  * Missing initialization flaws were found in the Linux kernel. A local,
  unprivileged user could use these flaws to cause information leaks.
  (CVE-2010-3876, CVE-2010-4072, CVE-2010-4073, CVE-2010-4075, CVE-2010-4080,
  CVE-2010-4083, CVE-2010-4158, Low)
  
  Red Hat would like to thank Alan Cox for reporting CVE-2010-4242; Vegard
  Nossum for reporting CVE-2010-4249; Vasiliy Kulikov for reporting
  CVE-2010-3876; Kees Cook for reporting CVE-2010-4072; and Dan Rosenberg for
  reporting CVE-2010-4073, CVE-2010-4075, CVE-2010-4080, CVE-2010-4083, and
  CVE-2010-4158.
  
  This update also fixes the following bugs:
  
  * A flaw was found in the Linux kernel where, if used in conjunction with
  another flaw that can result in a kernel Oops, could possibly lead to
  privilege escalation. It does not affect Red Hat Enterprise Linux 4 as the
  sysctl panic_on_oops variable is turned on by default. However, as a
  preventive measure if the variable is turned off by an administrator, this
  update addresses the issue. Red Hat would like to thank Nelson Elhage for
  reporting this vulnerability. (BZ#659568)
  
  * On Intel I/O Controller Hub 9 (ICH9) hardware, jumbo frame support is
  achieved by using page-based sk_buff buffers without any packet split. The
  entire frame data is copied to the page(s) rather than some to the
  skb-&gt;data area and some to the page(s) when performing a typical
  packet-split. This caused problems with the filtering code and frames were
  getting dropped before they were received by list ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on CentOS 4";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-January/017246.html");
  script_id(881399);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:44:54 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-3859", "CVE-2010-3876", "CVE-2010-4072", "CVE-2010-4073",
                "CVE-2010-4075", "CVE-2010-4080", "CVE-2010-4083", "CVE-2010-4157",
                "CVE-2010-4158", "CVE-2010-4242", "CVE-2010-4249", "CVE-2010-4258");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2011:0162");
  script_name("CentOS Update for kernel CESA-2011:0162 centos4 x86_64");

  script_description(desc);
  script_summary("Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp", rpm:"kernel-largesmp~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp-devel", rpm:"kernel-largesmp-devel~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}