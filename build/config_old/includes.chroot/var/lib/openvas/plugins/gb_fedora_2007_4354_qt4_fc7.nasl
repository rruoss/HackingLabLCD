###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for qt4 FEDORA-2007-4354
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
tag_insight = "Qt is a software toolkit for developing applications.

  This package contains base tools, like string, xml, and network
  handling.";

tag_affected = "qt4 on Fedora 7";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-January/msg00131.html");
  script_id(860974);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-24 14:29:46 +0100 (Tue, 24 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "FEDORA", value: "2007-4354");
  script_cve_id("CVE-2007-5965");
  script_name( "Fedora Update for qt4 FEDORA-2007-4354");

  script_description(desc);
  script_summary("Check for the Version of qt4");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"qt4", rpm:"qt4~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4", rpm:"qt4~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-devel", rpm:"qt4-devel~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-mysql", rpm:"qt4-mysql~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-debuginfo", rpm:"qt4-debuginfo~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-sqlite", rpm:"qt4-sqlite~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-x11", rpm:"qt4-x11~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-postgresql", rpm:"qt4-postgresql~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-odbc", rpm:"qt4-odbc~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-doc", rpm:"qt4-doc~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-sqlite", rpm:"qt4-sqlite~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-odbc", rpm:"qt4-odbc~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-debuginfo", rpm:"qt4-debuginfo~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-postgresql", rpm:"qt4-postgresql~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-doc", rpm:"qt4-doc~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-devel", rpm:"qt4-devel~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-x11", rpm:"qt4-x11~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4-mysql", rpm:"qt4-mysql~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt4", rpm:"qt4~4.3.3~1.fc7", rls:"FC7")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
