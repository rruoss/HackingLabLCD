###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for w3m SUSE-SA:2007:005
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
tag_insight = "A format string problem in w3m -dump / -backend mode could be used
  by a malicious server to crash w3m or execute code.

  In SUSE Linux 10.1, openSUSE 10.2 and SUSE Linux Enterprise Server
  and Desktop 10 this problem was not exploitable to execute code due
  to use of the FORTIFY SOURCE extensions.

  This problem is tracked by the Mitre CVE ID CVE-2006-6772.";

tag_impact = "remote denial of service, remote code execution";
tag_affected = "w3m on Novell Linux Desktop 9, Novell Linux POS 9, Open Enterprise Server, openSUSE 10.2, SUSE LINUX 10.1, SuSE Linux Enterprise Server 8, SUSE SLED 10, SUSE SLES 10, SUSE SLES 9";
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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2007_05_w3m.html");
  script_id(850065);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "SUSE-SA", value: "2007-005");
  script_cve_id("CVE-2006-6772");
  script_name( "SuSE Update for w3m SUSE-SA:2007:005");

  script_description(desc);
  script_summary("Check for the Version of w3m");
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

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.1~41.2", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES10")
{

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.4.1_m17n_20030308~201.3", rls:"SLES10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.3.1~205", rls:"SLES10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.1~19.5", rls:"SLES10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESSr8")
{

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.4.1_m17n_20030308~201.3", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.3.1~205", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.1~19.5", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.4.1_m17n_20030308~201.3", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.3.1~205", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.1~19.5", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.4.1_m17n_20030308~201.3", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.3.1~205", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.1~19.5", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.4.1_m17n_20030308~201.3", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.3.1~205", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.1~19.5", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.4.1_m17n_20030308~201.3", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.3.1~205", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.1~19.5", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.1~19.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLED10")
{

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.4.1_m17n_20030308~201.3", rls:"SLED10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.3.1~205", rls:"SLED10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.1~19.5", rls:"SLED10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
