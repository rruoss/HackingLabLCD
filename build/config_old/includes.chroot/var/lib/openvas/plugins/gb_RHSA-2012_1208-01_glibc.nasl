###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for glibc RHSA-2012:1208-01
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
tag_insight = "The glibc packages provide the standard C and standard math libraries used
  by multiple programs on the system. Without these libraries, the Linux
  system cannot function properly.

  Multiple integer overflow flaws, leading to stack-based buffer overflows,
  were found in glibc's functions for converting a string to a numeric
  representation (strtod(), strtof(), and strtold()). If an application used
  such a function on attacker controlled input, it could cause the
  application to crash or, potentially, execute arbitrary code.
  (CVE-2012-3480)

  All users of glibc are advised to upgrade to these updated packages, which
  contain a backported patch to correct these issues.";

tag_affected = "glibc on Red Hat Enterprise Linux Desktop (v. 6),
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-August/msg00028.html");
  script_id(870816);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-28 10:25:46 +0530 (Tue, 28 Aug 2012)");
  script_cve_id("CVE-2012-3480");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "RHSA", value: "2012:1208-01");
  script_name("RedHat Update for glibc RHSA-2012:1208-01");

  script_description(desc);
  script_summary("Check for the Version of glibc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.12~1.80.el6_3.5", rls:"RHENT_6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.12~1.80.el6_3.5", rls:"RHENT_6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.12~1.80.el6_3.5", rls:"RHENT_6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo-common", rpm:"glibc-debuginfo-common~2.12~1.80.el6_3.5", rls:"RHENT_6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.12~1.80.el6_3.5", rls:"RHENT_6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.12~1.80.el6_3.5", rls:"RHENT_6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.12~1.80.el6_3.5", rls:"RHENT_6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.12~1.80.el6_3.5", rls:"RHENT_6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}