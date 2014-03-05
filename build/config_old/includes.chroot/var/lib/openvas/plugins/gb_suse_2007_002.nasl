###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for mono-web SUSE-SA:2007:002
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
tag_insight = "A security problem was found and fixed in the Mono / C# web server
  implementation.

  By appending spaces to URLs attackers could download the source code
  of ASP.net scripts that would normally get executed by the web server.

  This issue is tracked by the Mitre CVE ID CVE-2006-6104 and only
  affects SUSE Linux 10.1, openSUSE 10.2 and SUSE Linux Enterprise 10.

  Older products are not affected.

  The updated packages for this problem were released on December 29th 2006.";

tag_impact = "remote source code disclosure";
tag_affected = "mono-web on openSUSE 10.2, SUSE LINUX 10.1, SUSE SLED 10, SUSE SLES 10";
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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2007_02_mono.html");
  script_id(850112);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "SUSE-SA", value: "2007-002");
  script_cve_id("CVE-2006-6104");
  script_name( "SuSE Update for mono-web SUSE-SA:2007:002");

  script_description(desc);
  script_summary("Check for the Version of mono-web");
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

if(release == "SLED10")
{

  if ((res = isrpmvuln(pkg:"bytefx-data-mysql", rpm:"bytefx-data-mysql~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-basic", rpm:"mono-basic~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-core", rpm:"mono-core~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-core-32bit", rpm:"mono-core-32bit~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data", rpm:"mono-data~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-firebird", rpm:"mono-data-firebird~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-oracle", rpm:"mono-data-oracle~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-postgresql", rpm:"mono-data-postgresql~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-sqlite", rpm:"mono-data-sqlite~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-sybase", rpm:"mono-data-sybase~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-devel", rpm:"mono-devel~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-extras", rpm:"mono-extras~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-jscript", rpm:"mono-jscript~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-locale-extras", rpm:"mono-locale-extras~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-nunit", rpm:"mono-nunit~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-web", rpm:"mono-web~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-winforms", rpm:"mono-winforms~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibm-data-db2", rpm:"ibm-data-db2~1.1.13.8~2.15", rls:"SLED10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"bytefx-data-mysql", rpm:"bytefx-data-mysql~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibm-data-db2", rpm:"ibm-data-db2~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-core", rpm:"mono-core~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data", rpm:"mono-data~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-firebird", rpm:"mono-data-firebird~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-oracle", rpm:"mono-data-oracle~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-postgresql", rpm:"mono-data-postgresql~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-sqlite", rpm:"mono-data-sqlite~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-sybase", rpm:"mono-data-sybase~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-devel", rpm:"mono-devel~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-extras", rpm:"mono-extras~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-jscript", rpm:"mono-jscript~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-locale-extras", rpm:"mono-locale-extras~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-nunit", rpm:"mono-nunit~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-web", rpm:"mono-web~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-winforms", rpm:"mono-winforms~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-core-32bit", rpm:"mono-core-32bit~1.1.18.1~12.2", rls:"openSUSE10.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES10")
{

  if ((res = isrpmvuln(pkg:"bytefx-data-mysql", rpm:"bytefx-data-mysql~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-basic", rpm:"mono-basic~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-core", rpm:"mono-core~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-core-32bit", rpm:"mono-core-32bit~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data", rpm:"mono-data~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-firebird", rpm:"mono-data-firebird~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-oracle", rpm:"mono-data-oracle~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-postgresql", rpm:"mono-data-postgresql~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-sqlite", rpm:"mono-data-sqlite~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-sybase", rpm:"mono-data-sybase~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-devel", rpm:"mono-devel~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-extras", rpm:"mono-extras~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-jscript", rpm:"mono-jscript~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-locale-extras", rpm:"mono-locale-extras~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-nunit", rpm:"mono-nunit~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-web", rpm:"mono-web~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-winforms", rpm:"mono-winforms~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibm-data-db2", rpm:"ibm-data-db2~1.1.13.8~2.15", rls:"SLES10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"bytefx-data-mysql", rpm:"bytefx-data-mysql~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibm-data-db2", rpm:"ibm-data-db2~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-basic", rpm:"mono-basic~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-core", rpm:"mono-core~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data", rpm:"mono-data~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-firebird", rpm:"mono-data-firebird~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-oracle", rpm:"mono-data-oracle~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-postgresql", rpm:"mono-data-postgresql~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-sqlite", rpm:"mono-data-sqlite~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-data-sybase", rpm:"mono-data-sybase~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-devel", rpm:"mono-devel~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-extras", rpm:"mono-extras~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-jscript", rpm:"mono-jscript~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-locale-extras", rpm:"mono-locale-extras~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-nunit", rpm:"mono-nunit~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-web", rpm:"mono-web~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mono-winforms", rpm:"mono-winforms~1.1.13.8~2.15", rls:"SL10.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
