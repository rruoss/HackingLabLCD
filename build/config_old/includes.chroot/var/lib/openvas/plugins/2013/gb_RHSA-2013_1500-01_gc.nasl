###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for gc RHSA-2013:1500-01
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

if(description)
{
  script_id(871068);
  script_version("$Revision: 61 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-11-12 14:24:03 +0100 (Di, 12. Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-08 10:42:36 +0530 (Fri, 08 Nov 2013)");
  script_cve_id("CVE-2012-2673");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("RedHat Update for gc RHSA-2013:1500-01");

  tag_insight = "gc is a Boehm-Demers-Weiser conservative garbage collector for C and C++.

It was discovered that gc's implementation of the malloc() and calloc()
routines did not properly perform parameter sanitization when allocating
memory. If an application using gc did not implement application-level
validity checks for the malloc() and calloc() routines, a remote attacker
could provide specially crafted application-specific input, which, when
processed by the application, could lead to an application crash or,
potentially, arbitrary code execution with the privileges of the user
running the application. (CVE-2012-2673)

Users of gc are advised to upgrade to these updated packages, which contain
backported patches to correct this issue. Applications using gc must be
restarted for the update to take effect.
";

  tag_affected = "gc on Red Hat Enterprise Linux Desktop (v. 6),
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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_description(desc);
  script_xref(name: "RHSA", value: "2013:1500-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-November/msg00000.html");
  script_summary("Check for the Version of gc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
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

  if ((res = isrpmvuln(pkg:"gc", rpm:"gc~7.1~12.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gc-debuginfo", rpm:"gc-debuginfo~7.1~12.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
