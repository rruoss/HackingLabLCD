###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libvirt RHSA-2013:0831-01
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
tag_insight = "The libvirt library is a C API for managing and interacting with the
  virtualization capabilities of Linux and other operating systems. In
  addition, libvirt provides tools for remote management of virtualized
  systems.

  It was found that libvirtd leaked file descriptors when listing all volumes
  for a particular pool. A remote attacker able to establish a read-only
  connection to libvirtd could use this flaw to cause libvirtd to consume all
  available file descriptors, preventing other users from using libvirtd
  services (such as starting a new guest) until libvirtd is restarted.
  (CVE-2013-1962)

  Red Hat would like to thank Edoardo Comar of IBM for reporting this issue.

  This update also fixes the following bugs:

  * Previously, libvirt made control group (cgroup) requests on files that
  it should not have. With older kernels, such nonsensical cgroup requests
  were ignored; however, newer kernels are stricter, resulting in libvirt
  logging spurious warnings and failures to the libvirtd and audit logs. The
  audit log failures displayed by the ausearch tool were similar to the
  following:

  root    [date] - failed     cgroup     allow     path     rw     /dev/kqemu

  With this update, libvirt no longer attempts the nonsensical cgroup
  actions, leaving only valid attempts in the libvirtd and audit logs (making
  it easier to search for real cases of failure). (BZ#958837)

  * Previously, libvirt used the wrong variable when constructing audit
  messages. This led to invalid audit messages, causing ausearch to format
  certain entries as having path=(null) instead of the correct path. This
  could prevent ausearch from locating events related to cgroup device ACL
  modifications for guests managed by libvirt. With this update, the audit
  messages are generated correctly, preventing loss of audit coverage.
  (BZ#958839)

  All users of libvirt are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. After installing
  the updated packages, libvirtd will be restarted automatically.";


tag_affected = "libvirt on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
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
  script_id(870994);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-17 09:49:36 +0530 (Fri, 17 May 2013)");
  script_cve_id("CVE-2013-1962");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("RedHat Update for libvirt RHSA-2013:0831-01");

  script_description(desc);
  script_xref(name: "RHSA", value: "2013:0831-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-May/msg00015.html");
  script_summary("Check for the Version of libvirt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~18.el6_4.5", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~18.el6_4.5", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-debuginfo", rpm:"libvirt-debuginfo~0.10.2~18.el6_4.5", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~18.el6_4.5", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~18.el6_4.5", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}