###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for hypervkvpd RHSA-2013:0807-01
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
tag_insight = "The hypervkvpd package contains hypervkvpd, the guest Microsoft Hyper-V
  Key-Value Pair (KVP) daemon. The daemon passes basic information to the
  host through VMBus, such as the guest IP address, fully qualified domain
  name, operating system name, and operating system release number.

  A denial of service flaw was found in the way hypervkvpd processed certain
  Netlink messages. A local, unprivileged user in a guest (running on
  Microsoft Hyper-V) could send a Netlink message that, when processed, would
  cause the guest's hypervkvpd daemon to exit. (CVE-2012-5532)

  The CVE-2012-5532 issue was discovered by Florian Weimer of the Red Hat
  Product Security Team.

  This update also fixes the following bug:

  * The hypervkvpd daemon did not close the file descriptors for pool files
  when they were updated. This could eventually lead to hypervkvpd crashing
  with a KVP: Failed to open file, pool: 1 error after consuming all
  available file descriptors. With this update, the file descriptors are
  closed, correcting this issue. (BZ#953502)

  Users of hypervkvpd are advised to upgrade to this updated package, which
  contains backported patches to correct these issues. After installing the
  update, it is recommended to reboot all guest machines.";


tag_affected = "hypervkvpd on Red Hat Enterprise Linux (v. 5 server)";
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
  script_id(870992);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-13 12:42:38 +0530 (Mon, 13 May 2013)");
  script_cve_id("CVE-2012-5532");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("RedHat Update for hypervkvpd RHSA-2013:0807-01");

  script_description(desc);
  script_xref(name: "RHSA", value: "2013:0807-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-May/msg00005.html");
  script_summary("Check for the Version of hypervkvpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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

  if ((res = isrpmvuln(pkg:"hypervkvpd", rpm:"hypervkvpd~0~0.7.el5_9.3", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hypervkvpd-debuginfo", rpm:"hypervkvpd-debuginfo~0~0.7.el5_9.3", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
