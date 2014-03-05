###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for acroread SUSE-SA:2008:009
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
tag_insight = "This version update to 8.1.2 fixes numerous bugs, including some
  security problems.

  While Adobe did not publish any details about those problems yet,
  third parties have listed some.

  The official Adobe page is:
  http://www.adobe.com/support/security/advisories/apsa08-01.html

  CVE-2008-0655: Multiple unspecified vulnerabilities in Adobe Reader
  and Acrobat before 8.1.2 have unknown impact and
  attack vectors.

  CVE-2008-0667: The DOC.print function in the Adobe JavaScript API,
  as used by Adobe Acrobat and Reader before 8.1.2, allows
  remote attackers to configure silent non-interactive
  printing, and trigger the printing of an arbitrary
  number of copies of a document.

  CVE-2008-0726: Integer overflow in Adobe Reader and Acrobat 8.1.1 and
  earlier allows remote attackers to execute arbitrary
  code via crafted arguments to the printSepsWithParams,
  which triggers memory corruption.

  Packages for SUSE Linux Enterprise Server 9 and Novell Linux Desktop
  9 are not yet available, since we cannot upgrade to Acrobat Reader 8
  on those machines. As soon as a fixed Acrobat Reader 7 is released,
  they will receive updates.";

tag_impact = "remote code execution";
tag_affected = "acroread on SUSE LINUX 10.1, openSUSE 10.2, openSUSE 10.3, SUSE Linux Enterprise Desktop 10 SP1, SLE SDK 10 SP1, SUSE Linux Enterprise Server 10 SP1";
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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2008_09_acroread.html");
  script_id(850034);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "SUSE-SA", value: "2008-009");
  script_cve_id("CVE-2008-0655", "CVE-2008-0667", "CVE-2008-0726");
  script_name( "SuSE Update for acroread SUSE-SA:2008:009");

  script_description(desc);
  script_summary("Check for the Version of acroread");
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

if(release == "openSUSE10.3")
{

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.2~1.2", rls:"openSUSE10.3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.2~1.2", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.2~1.4", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"acroread_ja", rpm:"acroread_ja~8.1.2~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.2~1.4", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
