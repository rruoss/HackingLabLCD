###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for systemtap CESA-2012:0376 centos6 
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
tag_insight = "SystemTap is an instrumentation system for systems running the Linux
  kernel. The system allows developers to write scripts to collect data on
  the operation of the system.

  An invalid pointer read flaw was found in the way SystemTap handled
  malformed debugging information in DWARF format. When SystemTap
  unprivileged mode was enabled, an unprivileged user in the stapusr group
  could use this flaw to crash the system or, potentially, read arbitrary
  kernel memory. Additionally, a privileged user (root, or a member of the
  stapdev group) could trigger this flaw when tricked into instrumenting a
  specially-crafted ELF binary, even when unprivileged mode was not enabled.
  (CVE-2012-0875)
  
  SystemTap users should upgrade to these updated packages, which contain a
  backported patch to correct this issue.";

tag_affected = "systemtap on CentOS 6";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-March/018485.html");
  script_id(881130);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:18:16 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-0875");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2012:0376");
  script_name("CentOS Update for systemtap CESA-2012:0376 centos6 ");

  script_description(desc);
  script_summary("Check for the Version of systemtap");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"systemtap", rpm:"systemtap~1.6~5.el6_2", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-grapher", rpm:"systemtap-grapher~1.6~5.el6_2", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-initscript", rpm:"systemtap-initscript~1.6~5.el6_2", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-runtime", rpm:"systemtap-runtime~1.6~5.el6_2", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-sdt-devel", rpm:"systemtap-sdt-devel~1.6~5.el6_2", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-server", rpm:"systemtap-server~1.6~5.el6_2", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-testsuite", rpm:"systemtap-testsuite~1.6~5.el6_2", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}