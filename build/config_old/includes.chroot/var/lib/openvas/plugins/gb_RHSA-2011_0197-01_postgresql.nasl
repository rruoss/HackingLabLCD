###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for postgresql RHSA-2011:0197-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "PostgreSQL is an advanced object-relational database management system
  (DBMS).

  A stack-based buffer overflow flaw was found in the way PostgreSQL
  processed certain tokens from an SQL query when the intarray module was
  enabled on a particular database. An authenticated database user running a
  specially-crafted SQL query could use this flaw to cause a temporary denial
  of service (postgres daemon crash) or, potentially, execute arbitrary code
  with the privileges of the database server. (CVE-2010-4015)
  
  Red Hat would like to thank Geoff Keating of the Apple Product Security
  team for reporting this issue.
  
  For Red Hat Enterprise Linux 4, the updated postgresql packages contain a
  backported patch for this issue; there are no other changes.
  
  For Red Hat Enterprise Linux 5, the updated postgresql packages upgrade
  PostgreSQL to version 8.1.23, and contain a backported patch for this
  issue. Refer to the PostgreSQL Release Notes for a full list of changes:
  http://www.postgresql.org/docs/8.1/static/release.html
  
  For Red Hat Enterprise Linux 6, the updated postgresql packages upgrade
  PostgreSQL to version 8.4.7, which includes a fix for this issue. Refer to
  the PostgreSQL Release Notes for a full list of changes:
  http://www.postgresql.org/docs/8.4/static/release.html
  
  All PostgreSQL users are advised to upgrade to these updated packages,
  which correct this issue. If the postgresql service is running, it will be
  automatically restarted after installing this update.";

tag_affected = "postgresql on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-February/msg00002.html");
  script_id(870389);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-04 14:19:53 +0100 (Fri, 04 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "RHSA", value: "2011:0197-01");
  script_cve_id("CVE-2010-4015");
  script_name("RedHat Update for postgresql RHSA-2011:0197-01");

  script_description(desc);
  script_summary("Check for the Version of postgresql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.1.23~1.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.1.23~1.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-debuginfo", rpm:"postgresql-debuginfo~8.1.23~1.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.1.23~1.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.1.23~1.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~8.1.23~1.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-pl", rpm:"postgresql-pl~8.1.23~1.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-python", rpm:"postgresql-python~8.1.23~1.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.1.23~1.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-tcl", rpm:"postgresql-tcl~8.1.23~1.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~8.1.23~1.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-debuginfo", rpm:"postgresql-debuginfo~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-jdbc", rpm:"postgresql-jdbc~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-pl", rpm:"postgresql-pl~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-python", rpm:"postgresql-python~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-tcl", rpm:"postgresql-tcl~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~7.4.30~1.el4_8.2", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}