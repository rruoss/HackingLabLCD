###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2008:0055 centos4 x86_64
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

  These updated kernel packages fix the following security issues:
  
  A flaw was found in the virtual filesystem (VFS). A local unprivileged
  user could truncate directories to which they had write permission; this
  could render the contents of the directory inaccessible. (CVE-2008-0001,
  Important)
  
  A flaw was found in the implementation of ptrace. A local unprivileged user
  could trigger this flaw and possibly cause a denial of service (system
  hang). (CVE-2007-5500, Important)
  
  A flaw was found in the way the Red Hat Enterprise Linux 4 kernel handled
  page faults when a CPU used the NUMA method for accessing memory on Itanium
  architectures. A local unprivileged user could trigger this flaw and cause
  a denial of service (system panic). (CVE-2007-4130, Important)
  
  A possible NULL pointer dereference was found in the chrp_show_cpuinfo
  function when using the PowerPC architecture. This may have allowed a local
  unprivileged user to cause a denial of service (crash).
  (CVE-2007-6694, Moderate)
  
  A flaw was found in the way core dump files were created. If a local user
  can get a root-owned process to dump a core file into a directory, which
  the user has write access to, they could gain read access to that core
  file. This could potentially grant unauthorized access to sensitive
  information. (CVE-2007-6206, Moderate)
  
  Two buffer overflow flaws were found in the Linux kernel ISDN subsystem. A
  local unprivileged  user could use these flaws to cause a denial of
  service. (CVE-2007-6063, CVE-2007-6151, Moderate)
  
  As well, these updated packages fix the following bug:
  
  * when moving volumes that contain multiple segments, and a mirror segment
  is not the first in the mapping table, running the &quot;pvmove /dev/[device]
  /dev/[device]&quot; command caused a kernel panic. A &quot;kernel: Unable to handle
  kernel paging request at virtual address [address]&quot; error was logged by
  syslog.
  
  Red Hat Enterprise Linux 4 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.";

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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-February/014657.html");
  script_id(880141);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2008:0055");
  script_cve_id("CVE-2007-4130", "CVE-2007-5500", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6694", "CVE-2008-0001");
  script_name( "CentOS Update for kernel CESA-2008:0055 centos4 x86_64");

  script_description(desc);
  script_summary("Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~67.0.4.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~67.0.4.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~67.0.4.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp", rpm:"kernel-largesmp~2.6.9~67.0.4.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp-devel", rpm:"kernel-largesmp-devel~2.6.9~67.0.4.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~67.0.4.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~67.0.4.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~67.0.4.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~67.0.4.EL", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
