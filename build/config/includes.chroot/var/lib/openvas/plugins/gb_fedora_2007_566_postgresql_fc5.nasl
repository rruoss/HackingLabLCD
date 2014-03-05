###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for postgresql FEDORA-2007-566
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
tag_insight = "PostgreSQL is an advanced Object-Relational database management system
  (DBMS) that supports almost all SQL constructs (including
  transactions, subselects and user-defined types and functions). The
  postgresql package includes the client programs and libraries that
  you'll need to access a PostgreSQL DBMS server.  These PostgreSQL
  client programs are programs that directly manipulate the internal
  structure of PostgreSQL databases on a PostgreSQL server. These client
  programs can be located on the same machine with the PostgreSQL
  server, or may be on a remote machine which accesses a PostgreSQL
  server over a network connection. This package contains the docs
  in HTML for the whole package, as well as command-line utilities for
  managing PostgreSQL databases on a PostgreSQL server.

  If you want to manipulate a PostgreSQL database on a remote PostgreSQL
  server, you need this package. You also need to install this package
  if you're installing the postgresql-server package.";

tag_affected = "postgresql on Fedora Core 5";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-June/msg00065.html");
  script_id(861481);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:31:39 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "FEDORA", value: "2007-566");
  script_cve_id("CVE-2007-2138", "CVE-2007-0555", "CVE-2007-0556");
  script_name( "Fedora Update for postgresql FEDORA-2007-566");

  script_description(desc);
  script_summary("Check for the Version of postgresql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora_core", "login/SSH/success", "ssh/login/release");
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

if(release == "FC5")
{

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/postgresql-test", rpm:"x86_64/postgresql-test~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/postgresql-pl", rpm:"x86_64/postgresql-pl~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/postgresql-devel", rpm:"x86_64/postgresql-devel~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/postgresql-server", rpm:"x86_64/postgresql-server~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/postgresql-debuginfo", rpm:"x86_64/debug/postgresql-debuginfo~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/postgresql-contrib", rpm:"x86_64/postgresql-contrib~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/postgresql-libs", rpm:"x86_64/postgresql-libs~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/postgresql-tcl", rpm:"x86_64/postgresql-tcl~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/postgresql", rpm:"x86_64/postgresql~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/postgresql-python", rpm:"x86_64/postgresql-python~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/postgresql-jdbc", rpm:"x86_64/postgresql-jdbc~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/postgresql-docs", rpm:"x86_64/postgresql-docs~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/postgresql-test", rpm:"i386/postgresql-test~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/postgresql-python", rpm:"i386/postgresql-python~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/postgresql-tcl", rpm:"i386/postgresql-tcl~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/postgresql", rpm:"i386/postgresql~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/postgresql-contrib", rpm:"i386/postgresql-contrib~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/postgresql-server", rpm:"i386/postgresql-server~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/postgresql-devel", rpm:"i386/postgresql-devel~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/postgresql-libs", rpm:"i386/postgresql-libs~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/postgresql-jdbc", rpm:"i386/postgresql-jdbc~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/postgresql-debuginfo", rpm:"i386/debug/postgresql-debuginfo~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/postgresql-pl", rpm:"i386/postgresql-pl~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/postgresql-docs", rpm:"i386/postgresql-docs~8.1.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
