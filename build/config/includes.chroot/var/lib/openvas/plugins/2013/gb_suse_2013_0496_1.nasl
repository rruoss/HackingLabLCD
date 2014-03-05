###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for fix openSUSE-SU-2013:0496-1 (fix)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_id(850453);
  script_version("$Revision: 74 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-11-22 13:29:03 +0100 (Fri, 22 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:36 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-2492");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "openSUSE-SU", value: "2013:0496_1");
  script_name("SuSE Update for fix openSUSE-SU-2013:0496-1 (fix)");

  tag_insight = "
  This update fixes a bug which allows an unauthenticated
  remote attacker to cause a stack overflow in server code,
  resulting in either server crash or even code execution as
  the user running firebird.
  ";
  tag_affected = "fix on openSUSE 12.2, openSUSE 12.1";

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
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2013-03/msg00036.html");
  script_summary("Check for the Version of fix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"firebird", rpm:"firebird~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-classic", rpm:"firebird-classic~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-classic-debuginfo", rpm:"firebird-classic-debuginfo~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-classic-debugsource", rpm:"firebird-classic-debugsource~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-debuginfo", rpm:"firebird-debuginfo~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-debugsource", rpm:"firebird-debugsource~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-devel", rpm:"firebird-devel~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-superserver", rpm:"firebird-superserver~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-superserver-debuginfo", rpm:"firebird-superserver-debuginfo~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2", rpm:"libfbclient2~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-debuginfo", rpm:"libfbclient2-debuginfo~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-devel", rpm:"libfbclient2-devel~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed-devel", rpm:"libfbembed-devel~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2_5", rpm:"libfbembed2_5~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2_5-debuginfo", rpm:"libfbembed2_5-debuginfo~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-32bit", rpm:"firebird-32bit~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-debuginfo-32bit", rpm:"firebird-debuginfo-32bit~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-32bit", rpm:"libfbclient2-32bit~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-debuginfo-32bit", rpm:"libfbclient2-debuginfo-32bit~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-doc", rpm:"firebird-doc~2.5.2.26539~2.8.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE12.1")
{

  if ((res = isrpmvuln(pkg:"firebird", rpm:"firebird~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-classic", rpm:"firebird-classic~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-classic-debuginfo", rpm:"firebird-classic-debuginfo~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-debuginfo", rpm:"firebird-debuginfo~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-debugsource", rpm:"firebird-debugsource~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-devel", rpm:"firebird-devel~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-devel-debuginfo", rpm:"firebird-devel-debuginfo~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-doc", rpm:"firebird-doc~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-filesystem", rpm:"firebird-filesystem~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-superserver", rpm:"firebird-superserver~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firebird-superserver-debuginfo", rpm:"firebird-superserver-debuginfo~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2", rpm:"libfbclient2~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-debuginfo", rpm:"libfbclient2-debuginfo~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2", rpm:"libfbembed2~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2-debuginfo", rpm:"libfbembed2-debuginfo~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-32bit", rpm:"libfbclient2-32bit~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-debuginfo-32bit", rpm:"libfbclient2-debuginfo-32bit~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2-32bit", rpm:"libfbembed2-32bit~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2-debuginfo-32bit", rpm:"libfbembed2-debuginfo-32bit~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-debuginfo-x86", rpm:"libfbclient2-debuginfo-x86~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbclient2-x86", rpm:"libfbclient2-x86~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2-debuginfo-x86", rpm:"libfbembed2-debuginfo-x86~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfbembed2-x86", rpm:"libfbembed2-x86~2.1.3.18185.0~22.4.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
