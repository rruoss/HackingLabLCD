###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for php RHSA-2012:0093-01
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
tag_insight = "PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Server.

  It was discovered that the fix for CVE-2011-4885 (released via
  RHSA-2012:0071, RHSA-2012:0033, and RHSA-2012:0019 for php packages in Red
  Hat Enterprise Linux 4, 5, and 6 respectively) introduced an uninitialized
  memory use flaw. A remote attacker could send a specially-crafted HTTP
  request to cause the PHP interpreter to crash or, possibly, execute
  arbitrary code. (CVE-2012-0830)

  All php users should upgrade to these updated packages, which contain a
  backported patch to resolve this issue. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.";

tag_affected = "php on Red Hat Enterprise Linux (v. 5 server),
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
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-February/msg00016.html");
  script_id(870542);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-03 11:24:43 +0530 (Fri, 03 Feb 2012)");
  script_cve_id("CVE-2012-0830", "CVE-2011-4885");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "RHSA", value: "2012:0093-01");
  script_name("RedHat Update for php RHSA-2012:0093-01");

  script_description(desc);
  script_summary("Check for the Version of php");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"php", rpm:"php~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-common", rpm:"php-common~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ncurses", rpm:"php-ncurses~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~5.1.6~27.el5_7.5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"php", rpm:"php~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-domxml", rpm:"php-domxml~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ncurses", rpm:"php-ncurses~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear", rpm:"php-pear~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~4.3.9~3.36", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}