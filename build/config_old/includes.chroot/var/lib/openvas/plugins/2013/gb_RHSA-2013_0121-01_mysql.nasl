###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mysql RHSA-2013:0121-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  It was found that the fix for the CVE-2009-4030 issue, a flaw in the way
  MySQL checked the paths used as arguments for the DATA DIRECTORY and INDEX
  DIRECTORY directives when the 'datadir' option was configured with a
  relative path, was incorrectly removed when the mysql packages in Red Hat
  Enterprise Linux 5 were updated to version 5.0.95 via RHSA-2012:0127. An
  authenticated attacker could use this flaw to bypass the restriction
  preventing the use of subdirectories of the MySQL data directory being used
  as DATA DIRECTORY and INDEX DIRECTORY paths. This update re-applies the fix
  for CVE-2009-4030. (CVE-2012-4452)

  Note: If the use of the DATA DIRECTORY and INDEX DIRECTORY directives were
  disabled as described in RHSA-2010:0109 (by adding 'symbolic-links=0' to
  the '[mysqld]' section of the 'my.cnf' configuration file), users were not
  vulnerable to this issue.

  This issue was discovered by Karel Voln� of the Red Hat Quality Engineering
  team.

  This update also fixes the following bugs:

  * Prior to this update, the log file path in the logrotate script did not
  behave as expected. As a consequence, the logrotate function failed to
  rotate the '/var/log/mysqld.log' file. This update modifies the logrotate
  script to allow rotating the mysqld.log file. (BZ#647223)

  All MySQL users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing this
  update, the MySQL server daemon (mysqld) will be restarted automatically.";


tag_affected = "mysql on Red Hat Enterprise Linux (v. 5 server)";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2013-January/msg00004.html");
  script_id(870888);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:42:46 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2012-4452", "CVE-2009-4030");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "RHSA", value: "2013:0121-01");
  script_name("RedHat Update for mysql RHSA-2013:0121-01");

  script_description(desc);
  script_summary("Check for the Version of mysql");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.95~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}