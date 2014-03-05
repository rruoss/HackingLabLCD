# OpenVAS Vulnerability Test
# $Id: fcore_2009_13466.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-13466 (mysql)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries. The base package
contains the standard MySQL client programs and generic MySQL files.

Update Information:

- Update to MySQL 5.1.41, for various fixes described at
http://dev.mysql.com/doc/refman/5.1/en/news-5-1-41.html
including security fixes
- Stop waiting during service mysqld start if mysqld_safe exits

ChangeLog:

* Thu Dec 17 2009 Tom Lane  5.1.41-2
- Update to MySQL 5.1.41, for various fixes described at
http://dev.mysql.com/doc/refman/5.1/en/news-5-1-41.html
including fixes for CVE-2009-4019
Related: #540906
- Stop waiting during service mysqld start if mysqld_safe exits
Resolves: #544095
* Tue Nov 10 2009 Tom Lane  5.1.40-1
- Update to MySQL 5.1.40, for various fixes described at
http://dev.mysql.com/doc/refman/5.1/en/news-5-1-40.html
- Do not force the --log-error setting in mysqld init script
Resolves: #533736";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update mysql' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13466";
tag_summary = "The remote host is missing an update to mysql
announced via advisory FEDORA-2009-13466.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66573);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
 script_cve_id("CVE-2009-4019", "CVE-2009-4028");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Fedora Core 12 FEDORA-2009-13466 (mysql)");


 script_description(desc);

 script_summary("Fedora Core 12 FEDORA-2009-13466 (mysql)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Fedora Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=540906");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=541233");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.1.41~2.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.1.41~2.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-cluster", rpm:"mysql-cluster~5.1.41~2.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.1.41~2.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-embedded", rpm:"mysql-embedded~5.1.41~2.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-embedded-devel", rpm:"mysql-embedded-devel~5.1.41~2.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-libs", rpm:"mysql-libs~5.1.41~2.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.1.41~2.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.1.41~2.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~5.1.41~2.fc12", rls:"FC12")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
