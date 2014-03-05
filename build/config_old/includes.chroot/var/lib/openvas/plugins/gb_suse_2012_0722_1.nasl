###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for bind openSUSE-SU-2012:0722-1 (bind)
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
tag_affected = "bind on openSUSE 12.1, openSUSE 11.4";
tag_insight = "A remote denial of service in the bind nameserver via zero
  length rdata fields was fixed.";
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
  script_xref(name : "URL" , value : "http://195.135.221.135/opensuse-security-announce/2012-06/msg00005.html");
  script_id(850243);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:27 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2012-1667");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "openSUSE-SU", value: "2012:0722_1");
  script_name("SuSE Update for bind openSUSE-SU-2012:0722-1 (bind)");

  script_description(desc);
  script_summary("Check for the Version of bind");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs-debuginfo", rpm:"bind-libs-debuginfo~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-lwresd", rpm:"bind-lwresd~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-lwresd-debuginfo", rpm:"bind-lwresd-debuginfo~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs-debuginfo-32bit", rpm:"bind-libs-debuginfo-32bit~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs-debuginfo-x86", rpm:"bind-libs-debuginfo-x86~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ind-libs-x86", rpm:"ind-libs-x86~9.7.4P1~0.28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE12.1")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs-debuginfo", rpm:"bind-libs-debuginfo~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-lwresd", rpm:"bind-lwresd~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-lwresd-debuginfo", rpm:"bind-lwresd-debuginfo~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs-debuginfo-32bit", rpm:"bind-libs-debuginfo-32bit~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs-debuginfo-x86", rpm:"bind-libs-debuginfo-x86~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs-x86", rpm:"bind-libs-x86~9.8.1P1~4.11.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}