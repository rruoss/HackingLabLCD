###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for freetype2 SUSE-SA:2007:041
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
tag_insight = "The TTF rendering library freetype2 was updated to fix an integer
  signedness bug when handling TTF images.

  This bug can lead to a heap overflow that can be exploited to execute
  arbitrary code. CVE-2007-2754

  Updates for SLE 10 Service Pack 1 and SUSE Linux 10.1 were released on
  Monday the 2nd of July, all other products received them at June 20th.";

tag_impact = "remote code execution";
tag_affected = "freetype2 on SUSE LINUX 10.1, openSUSE 10.2, SuSE Linux Enterprise Server 8, SUSE SLES 9, Novell Linux Desktop 9, Open Enterprise Server, Novell Linux POS 9, SUSE Linux Enterprise Desktop 10 SP1, SUSE Linux Enterprise Server 10 SP1";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2007_41_freetype2.html");
  script_id(850084);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "SUSE-SA", value: "2007-041");
  script_cve_id("CVE-2007-2754");
  script_name( "SuSE Update for freetype2 SUSE-SA:2007:041");

  script_description(desc);
  script_summary("Check for the Version of freetype2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "HostDetails/OS/cpe:/o:suse:linux_enterprise_server", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
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

if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.2.1.20061027~15", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.2.1.20061027~15", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-32bit", rpm:"freetype2-32bit~2.2.1.20061027~15", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel-32bit", rpm:"freetype2-devel-32bit~2.2.1.20061027~15", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESSr8")
{

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.7~53.17", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.1.7~53.17", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.3~56", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.0.9~140", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.0.9~140", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.7~53.17", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.1.7~53.17", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.3~56", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.0.9~140", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.0.9~140", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.7~53.17", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.1.7~53.17", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.3~56", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.0.9~140", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.0.9~140", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.7~53.17", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.1.7~53.17", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.3~56", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.0.9~140", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.0.9~140", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.10~18.14", rls:"LES10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.1.10~18.14", rls:"LES10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.7~53.17", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.1.7~53.17", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.3~56", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.0.9~140", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.0.9~140", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.10~18.14", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.1.10~18.14", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.1.10~18.14", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.1.10~18.14", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
