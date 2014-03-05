#CESA-2009:1485 65755 2
# $Id: ovcesa2009_1485.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory CESA-2009:1485 (postgresql)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "For details on the issues addressed in this update,
please visit the referenced security advisories.";
tag_solution = "Update the appropriate packages on your system.

http://www.securityspace.com/smysecure/catid.html?in=CESA-2009:1485
http://www.securityspace.com/smysecure/catid.html?in=RHSA-2009:1485
https://rhn.redhat.com/errata/RHSA-2009-1485.html";
tag_summary = "The remote host is missing updates to postgresql announced in
advisory CESA-2009:1485.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(65755);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-13 18:25:40 +0200 (Tue, 13 Oct 2009)");
 script_cve_id("CVE-2009-3230", "CVE-2007-6600");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("CentOS Security Advisory CESA-2009:1485 (postgresql)");


 script_description(desc);

 script_summary("CentOS Security Advisory CESA-2009:1485 (postgresql)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("CentOS Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"rh-postgresql", rpm:"rh-postgresql~7.3.21~2", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rh-postgresql-contrib", rpm:"rh-postgresql-contrib~7.3.21~2", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rh-postgresql-devel", rpm:"rh-postgresql-devel~7.3.21~2", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rh-postgresql-docs", rpm:"rh-postgresql-docs~7.3.21~2", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rh-postgresql-jdbc", rpm:"rh-postgresql-jdbc~7.3.21~2", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rh-postgresql-libs", rpm:"rh-postgresql-libs~7.3.21~2", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rh-postgresql-pl", rpm:"rh-postgresql-pl~7.3.21~2", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rh-postgresql-python", rpm:"rh-postgresql-python~7.3.21~2", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rh-postgresql-server", rpm:"rh-postgresql-server~7.3.21~2", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rh-postgresql-tcl", rpm:"rh-postgresql-tcl~7.3.21~2", rls:"CentOS3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rh-postgresql-test", rpm:"rh-postgresql-test~7.3.21~2", rls:"CentOS3")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
