###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for clamav SUSE-SA:2007:017
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
tag_insight = "The anti-virus scan engine ClamAV was updated to the version 0.90 to
  fix various bugs including 2 security bugs:

  CVE-2007-0897: A file descriptor leak in the handling of CAB files can
  lead to a denial of service attack against the clamd scanner daemon
  caused by remote attackers.

  CVE-2007-0898: A directory traversal in handling of MIME E-Mail headers
  could be used by remote attackers to overwrite local files owned
  by the user under which clamd is running.
  Since clamd is running as &quot;vscan&quot; user on SUSE, it would only be able to
  overwrite files owned by &quot;vscan&quot;.";

tag_impact = "remote denial of service";
tag_affected = "clamav on SUSE LINUX 10.1, openSUSE 10.2, SUSE SLES 9, Open Enterprise Server, Novell Linux POS 9, SUSE SLES 10";
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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2007_17_clamav.html");
  script_id(850107);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "SUSE-SA", value: "2007-017");
  script_cve_id("CVE-2007-0897", "CVE-2007-0898");
  script_name( "SuSE Update for clamav SUSE-SA:2007:017");

  script_description(desc);
  script_summary("Check for the Version of clamav");
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

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES10")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~0.1", rls:"SLES10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~0.2", rls:"SLES10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~0.1", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~0.2", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~0.1", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~0.2", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~0.1", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~0.2", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~0.2", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
