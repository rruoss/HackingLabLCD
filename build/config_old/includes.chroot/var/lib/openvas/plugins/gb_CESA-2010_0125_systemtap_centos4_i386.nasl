###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for systemtap CESA-2010:0125 centos4 i386
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
tag_insight = "SystemTap is an instrumentation system for systems running the Linux
  kernel, version 2.6. Developers can write scripts to collect data on the
  operation of the system.

  A buffer overflow flaw was found in SystemTap's tapset __get_argv()
  function. If a privileged user ran a SystemTap script that called this
  function, a local, unprivileged user could, while that script is still
  running, trigger this flaw and cause memory corruption by running a command
  with a large argument list, which may lead to a system crash or,
  potentially, arbitrary code execution with root privileges. (CVE-2010-0411)
  
  Note: SystemTap scripts that call __get_argv(), being a privileged
  function, can only be executed by the root user or users in the stapdev
  group. As well, if such a script was compiled and installed by root, users
  in the stapusr group would also be able to execute it.
  
  SystemTap users should upgrade to these updated packages, which contain a
  backported patch to correct this issue.";

tag_affected = "systemtap on CentOS 4";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-March/016535.html");
  script_id(880371);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-05 12:48:43 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "CESA", value: "2010:0125");
  script_cve_id("CVE-2010-0411");
  script_name("CentOS Update for systemtap CESA-2010:0125 centos4 i386");

  script_description(desc);
  script_summary("Check for the Version of systemtap");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"systemtap", rpm:"systemtap~0.6.2~2.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-runtime", rpm:"systemtap-runtime~0.6.2~2.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemtap-testsuite", rpm:"systemtap-testsuite~0.6.2~2.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}