###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for qt3 SUSE-SA:2007:048
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
tag_impact = "remote code execution";
tag_affected = "qt3 on SUSE LINUX 10.1, openSUSE 10.2, SuSE Linux Enterprise Server 8, SUSE SLES 9, Novell Linux Desktop 9, Open Enterprise Server, Novell Linux POS 9, SUSE Linux Enterprise Desktop 10 SP1, SUSE Linux Enterprise Server 10 SP1";
tag_insight = "Format string bugs were found in several Qt warning messages.
  Applications using Qt for processing certain data types could
  trigger them if the data caused Qt to print warnings. The bugs
  potentially allow to execute arbitrary code via specially crafted
  files CVE-2007-3388.";
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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2007_48_qt3.html");
  script_id(850101);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "SUSE-SA", value: "2007-048");
  script_cve_id("CVE-2007-3388");
  script_name( "SuSE Update for qt3 SUSE-SA:2007:048");

  script_description(desc);
  script_summary("Check for the Version of qt3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "HostDetails/OS/cpe:/o:suse:linux_enterprise_server", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
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

if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.3.7~16", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel", rpm:"qt3-devel~3.3.7~16", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-static", rpm:"qt3-static~3.3.7~17", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-32bit", rpm:"qt3-32bit~3.3.7~16", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel-32bit", rpm:"qt3-devel-32bit~3.3.7~16", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESSr8")
{

  if ((res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.1.1~125", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.0.5~180", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel", rpm:"qt3-devel~3.0.5~180", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-mysql", rpm:"qt3-mysql~3.0.5~244", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-non-mt", rpm:"qt3-non-mt~3.0.5~244", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-postgresql", rpm:"qt3-postgresql~3.0.5~244", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-unixODBC", rpm:"qt3-unixODBC~3.0.5~244", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.3.1~36.29", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel", rpm:"qt3-devel~3.3.1~36.29", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-non-mt", rpm:"qt3-non-mt~3.3.1~41.27", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.3.1~36.29", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel", rpm:"qt3-devel~3.3.1~36.29", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-non-mt", rpm:"qt3-non-mt~3.3.1~41.27", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.3.1~36.29", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel", rpm:"qt3-devel~3.3.1~36.29", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-non-mt", rpm:"qt3-non-mt~3.3.1~41.27", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.3.5~58.29", rls:"LES10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-32bit", rpm:"qt3-32bit~3.3.5~58.29", rls:"LES10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel", rpm:"qt3-devel~3.3.5~58.29", rls:"LES10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel-32bit", rpm:"qt3-devel-32bit~3.3.5~58.29", rls:"LES10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.3.1~36.29", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel", rpm:"qt3-devel~3.3.1~36.29", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-non-mt", rpm:"qt3-non-mt~3.3.1~41.27", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.3.5~58.29", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-32bit", rpm:"qt3-32bit~3.3.5~58.29", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel", rpm:"qt3-devel~3.3.5~58.29", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel-32bit", rpm:"qt3-devel-32bit~3.3.5~58.29", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"qt3", rpm:"qt3~3.3.5~58.29", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-devel", rpm:"qt3-devel~3.3.5~58.29", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt3-static", rpm:"qt3-static~3.3.5~58.23", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}