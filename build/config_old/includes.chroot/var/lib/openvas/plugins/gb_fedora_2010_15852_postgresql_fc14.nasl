###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for postgresql FEDORA-2010-15852
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

  If you want to manipulate a PostgreSQL database on a local or remote PostgreSQL
  server, you need this package. You also need to install this package
  if you're installing the postgresql-server package.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "postgresql on Fedora 14";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049496.html");
  script_id(862597);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-02 08:39:14 +0100 (Thu, 02 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "FEDORA", value: "2010-15852");
  script_cve_id("CVE-2010-3433");
  script_name("Fedora Update for postgresql FEDORA-2010-15852");

  script_description(desc);
  script_summary("Check for the Version of postgresql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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

if(release == "FC14")
{

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.4.5~1.fc14", rls:"FC14")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
