###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2011:1163-01
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
tag_insight = "The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update includes backported fixes for two security issues. These issues
  only affected users of Red Hat Enterprise Linux 5.6 Extended Update
  Support, as they have already been addressed for users of Red Hat
  Enterprise Linux 5 in the 5.7 update, RHSA-2011:1065.
  
  This update fixes the following security issues:
  
  * A flaw was found in the way the Xen hypervisor implementation handled
  instruction emulation during virtual machine exits. A malicious user-space
  process running in an SMP guest could trick the emulator into reading a
  different instruction than the one that caused the virtual machine to exit.
  An unprivileged guest user could trigger this flaw to crash the host. This
  only affects systems with both an AMD x86 processor and the AMD
  Virtualization (AMD-V) extensions enabled. (CVE-2011-1780, Important)
  
  * A flaw allowed the tc_fill_qdisc() function in the Linux kernel's packet
  scheduler API implementation to be called on built-in qdisc structures. A
  local, unprivileged user could use this flaw to trigger a NULL pointer
  dereference, resulting in a denial of service. (CVE-2011-2525, Moderate)
  
  This update also fixes the following bugs:
  
  * A bug was found in the way the x86_emulate() function handled the IMUL
  instruction in the Xen hypervisor. On systems without support for hardware
  assisted paging (HAP), such as those running CPUs that do not have support
  for (or those that have it disabled) Intel Extended Page Tables (EPT) or
  AMD Virtualization (AMD-V) Rapid Virtualization Indexing (RVI), this bug
  could cause fully-virtualized guests to crash or lead to silent memory
  corruption. In reported cases, this issue occurred when booting
  fully-virtualized Red Hat Enterprise Linux 6.1 guests with memory cgroups
  enabled. (BZ#712884)
  
  * A bug in the way the ibmvscsi driver handled interrupts may have
  prevented automatic path recovery for multipath devices. This bug only
  affected 64-bit PowerPC systems. (BZ#720929)
  
  * The RHSA-2009:1243 update introduced a regression in the way file locking
  on NFS (Network File System) was handled. This caused applications to hang
  if they made a lock request on a file on an NFS version 2 or 3 file system
  that was mounted with the &quot;sec=krb5&quot; option. With this update, the original
  behavior of using mixed RPC authentication flavors for NFS and locking
  requests has been restored. (BZ#722854)
  
  Users should upgrade to these updated packages, which contain backported
  patches to resolve these issues. The system must be rebooted for this
  update to take effect.";

tag_affected = "kernel on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-August/msg00012.html");
  script_id(870470);
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-19 15:17:22 +0200 (Fri, 19 Aug 2011)");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "RHSA", value: "2011:1163-01");
  script_cve_id("CVE-2011-1780", "CVE-2011-2525");
  script_name("RedHat Update for kernel RHSA-2011:1163-01");

  script_description(desc);
  script_summary("Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~238.21.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
