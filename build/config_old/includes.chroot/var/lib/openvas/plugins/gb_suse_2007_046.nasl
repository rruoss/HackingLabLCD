###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for flash-player SUSE-SA:2007:046
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
tag_insight = "The Adobe Flash Player was updated to fix various security issues.

  New versions:
  - Flash 7.0.70.0: SUSE Linux 10.0, Novell Linux Desktop 9,
  SUSE Linux Desktop 1.0 and SUSE Linux Enterprise Server 8

  - Flash 9.0.48.0: SUSE Linux 10.1, openSUSE 10.2 and SUSE Linux
  Enterprise Desktop 10.

  Security issues resolved:
  - CVE-2007-3456: An input validation error has been identified in
  Flash Player 9.0.45.0 and earlier versions that could lead to the
  potential execution of arbitrary code.  This vulnerability could
  be accessed through content delivered from a remote location via
  the user's web browser, email client, or other applications that
  include or reference the Flash Player.

  - CVE-2007-3457: An issue with insufficient validation of the HTTP
  Referer has been identified in Flash Player 8.0.34.0 and
  earlier. This issue does not affect Flash Player 9. This issue
  could potentially aid an attacker in executing a cross-site request
  forgery attack.

  - CVE-2007-2022: The Linux and Solaris updates for Flash Player 7
  (7.0.70.0) address the issues with Flash Player and the Opera and
  Konqueror browsers described in Security Advisory APSA07-03. These
  issues do not impact Flash Player 9 on Linux or Solaris.

  The web browsers Opera and konqueror that were affected by CVE-2007-2022
  have already been fixed independently.";

tag_impact = "remote code execution";
tag_affected = "flash-player on SUSE LINUX 10.1, openSUSE 10.2, SuSE Linux Enterprise Server 8, Novell Linux Desktop 9, SUSE Linux Enterprise Desktop 10 SP1";
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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2007_46_flashplayer.html");
  script_id(850114);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "SUSE-SA", value: "2007-046");
  script_cve_id("CVE-2007-2022", "CVE-2007-3456", "CVE-2007-3457");
  script_name( "SuSE Update for flash-player SUSE-SA:2007:046");

  script_description(desc);
  script_summary("Check for the Version of flash-player");
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

if(release == "SLESSr8")
{

  if ((res = isrpmvuln(pkg:"netscape-plugins", rpm:"netscape-plugins~7.0.70~0.1", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"netscape-plugins", rpm:"netscape-plugins~4.80~116", rls:"SLESSr8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~9.0.48.0~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~7.0.70.0~0.1", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~9.0.48.0~1.2", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~7.0.70.0~0.1", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~9.0.48.0~1.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~9.0.48.0~1.2", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
