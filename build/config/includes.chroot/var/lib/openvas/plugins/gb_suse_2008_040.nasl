###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for postfix SUSE-SA:2008:040
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
tag_impact = "local privilege escalation";
tag_affected = "postfix on openSUSE 10.2, openSUSE 10.3, openSUSE 11.0, SuSE Linux Enterprise Server 8, SUSE SLES 9, Novell Linux Desktop 9, Open Enterprise Server, Novell Linux POS 9, SUSE Linux Enterprise Desktop 10 SP1, SUSE Linux Enterprise Server 10 SP1, SUSE Linux Enterprise Desktop 10 SP2, SUSE Linux Enterprise Server 10 SP2";
tag_insight = "Postfix is a well known MTA.
  During a source code audit the SuSE Security-Team discovered a local
  privilege escalation bug CVE-2008-2936 as well as a mailbox ownership
  problem CVE-2008-2937 in postfix.
  The first bug allowed local users to execute arbitrary commands as root
  while the second one allowed local users to read other users mail.";
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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2008_40_postfix.html");
  script_id(850031);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "SUSE-SA", value: "2008-040");
  script_cve_id("CVE-2008-2936", "CVE-2008-2937");
  script_name( "SuSE Update for postfix SUSE-SA:2008:040");

  script_description(desc);
  script_summary("Check for the Version of postfix");
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

if(release == "openSUSE10.3")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.4.5~20.4", rls:"openSUSE10.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~2.4.5~20.4", rls:"openSUSE10.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~2.4.5~20.4", rls:"openSUSE10.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-postgresql", rpm:"postfix-postgresql~2.4.5~20.4", rls:"openSUSE10.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.3.2~32", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~2.3.2~32", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~2.3.2~32", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-postgresql", rpm:"postfix-postgresql~2.3.2~32", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESSr8")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.26", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.1.1~1.24", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.25.3", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.26", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.1.1~1.24", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.25.3", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.26", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.1.1~1.24", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.25.3", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.26", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.1.1~1.24", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.25.3", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP2")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.26", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.1.1~1.24", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.25.3", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.26", rls:"LES10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.1.1~1.24", rls:"LES10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.25.3", rls:"LES10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.26", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.1.1~1.24", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.25.3", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP2")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.26", rls:"SLESDk10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.1.1~1.24", rls:"SLESDk10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.25.3", rls:"SLESDk10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.1.1~1.24", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.9~10.25.3", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.0")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.5.1~28.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-devel", rpm:"postfix-devel~2.5.1~28.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-mysql", rpm:"postfix-mysql~2.5.1~28.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-postgresql", rpm:"postfix-postgresql~2.5.1~28.3", rls:"openSUSE11.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}