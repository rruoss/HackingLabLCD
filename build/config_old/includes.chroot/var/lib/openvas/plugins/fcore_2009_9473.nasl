# OpenVAS Vulnerability Test
# $Id: fcore_2009_9473.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-9473 (postgresql)
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
tag_insight = "Update Information:

Update to PostgreSQL 8.3.8, for various fixes described at
http://www.postgresql.org/docs/8.3/static/release-8-3-8.html
including three security issues.

ChangeLog:

* Wed Sep  9 2009 Tom Lane  8.3.8-1
- Update to PostgreSQL 8.3.8, for various fixes described at
http://www.postgresql.org/docs/8.3/static/release-8-3-8.html
including three security issues
Related: #522084
Related: #522085
Related: #522092";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update postgresql' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9473";
tag_summary = "The remote host is missing an update to postgresql
announced via advisory FEDORA-2009-9473.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64850);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
 script_cve_id("CVE-2007-6600");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Fedora Core 11 FEDORA-2009-9473 (postgresql)");


 script_description(desc);

 script_summary("Fedora Core 11 FEDORA-2009-9473 (postgresql)");

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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=522084");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=522085");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=522092");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-libs", rpm:"postgresql-libs~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-python", rpm:"postgresql-python~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-tcl", rpm:"postgresql-tcl~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-debuginfo", rpm:"postgresql-debuginfo~8.3.8~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
