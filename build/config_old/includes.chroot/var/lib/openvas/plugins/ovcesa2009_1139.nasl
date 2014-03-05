#CESA-2009:1139 64374 2
# $Id: ovcesa2009_1139.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory CESA-2009:1139 (pidgin)
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

http://www.securityspace.com/smysecure/catid.html?in=CESA-2009:1139
http://www.securityspace.com/smysecure/catid.html?in=RHSA-2009:1139
https://rhn.redhat.com/errata/RHSA-2009-1139.html";
tag_summary = "The remote host is missing updates to pidgin announced in
advisory CESA-2009:1139.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64374);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-06 20:36:15 +0200 (Mon, 06 Jul 2009)");
 script_cve_id("CVE-2009-1889");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("CentOS Security Advisory CESA-2009:1139 (pidgin)");


 script_description(desc);

 script_summary("CentOS Security Advisory CESA-2009:1139 (pidgin)");

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
if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.5.8~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.5.8~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.5.8~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.5.8~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.5.8~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.5.8~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.5.8~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.5.8~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.5.8~1.el5", rls:"CentOS5")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
