###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for postgresql CESA-2012:1263 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

  It was found that the optional PostgreSQL xml2 contrib module allowed local
  files and remote URLs to be read and written to with the privileges of the
  database server when parsing Extensible Stylesheet Language Transformations
  (XSLT). An unprivileged database user could use this flaw to read and write
  to local files (such as the database's configuration files) and remote URLs
  they would otherwise not have access to by issuing a specially-crafted SQL
  query. (CVE-2012-3488)
  
  It was found that the &quot;xml&quot; data type allowed local files and remote URLs
  to be read with the privileges of the database server to resolve DTD and
  entity references in the provided XML. An unprivileged database user could
  use this flaw to read local files they would otherwise not have access to
  by issuing a specially-crafted SQL query. Note that the full contents of
  the files were not returned, but portions could be displayed to the user
  via error messages. (CVE-2012-3489)
  
  Red Hat would like to thank the PostgreSQL project for reporting these
  issues. Upstream acknowledges Peter Eisentraut as the original reporter of
  CVE-2012-3488, and Noah Misch as the original reporter of CVE-2012-3489.
  
  These updated packages upgrade PostgreSQL to version 8.4.13. Refer to the
  PostgreSQL Release Notes for a list of changes:
  
  <a  rel= &qt nofollow &qt  href= &qt http://www.postgresql.org/docs/8.4/static/release-8-4-13.html &qt >http://www.postgresql.org/docs/8.4/static/release-8-4-13.html</a>
  
  All PostgreSQL users are advised to upgrade to these updated packages,
  which correct these issues. If the postgresql service is running, it will
  be automatically restarted after installing this update.";

tag_affected = "postgresql on CentOS 6";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-September/018874.html");
  script_id(881502);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-17 16:50:31 +0530 (Mon, 17 Sep 2012)");
  script_cve_id("CVE-2012-3488", "CVE-2012-3489");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2012:1263");
  script_name("CentOS Update for postgresql CESA-2012:1263 centos6 ");

  script_description(desc);
  script_summary("Check for the Version of postgresql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.4.13~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.4.13~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.4.13~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.4.13~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~8.4.13~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~8.4.13~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~8.4.13~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~8.4.13~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.4.13~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~8.4.13~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}