#CESA-2009:1459 64989 4
# $Id: ovcesa2009_1459.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory CESA-2009:1459 (cyrus-imapd)
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

http://www.securityspace.com/smysecure/catid.html?in=CESA-2009:1459
http://www.securityspace.com/smysecure/catid.html?in=RHSA-2009:1459
https://rhn.redhat.com/errata/RHSA-2009-1459.html";
tag_summary = "The remote host is missing updates to cyrus-imapd announced in
advisory CESA-2009:1459.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64989);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
 script_cve_id("CVE-2009-2632", "CVE-2009-3235");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("CentOS Security Advisory CESA-2009:1459 (cyrus-imapd)");


 script_description(desc);

 script_summary("CentOS Security Advisory CESA-2009:1459 (cyrus-imapd)");

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
if ((res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.2.12~10.el4_8.4", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-devel", rpm:"cyrus-imapd-devel~2.2.12~10.el4_8.4", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-murder", rpm:"cyrus-imapd-murder~2.2.12~10.el4_8.4", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-nntp", rpm:"cyrus-imapd-nntp~2.2.12~10.el4_8.4", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-utils", rpm:"cyrus-imapd-utils~2.2.12~10.el4_8.4", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Cyrus", rpm:"perl-Cyrus~2.2.12~10.el4_8.4", rls:"CentOS4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.3.7~7.el5_4.3", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-devel", rpm:"cyrus-imapd-devel~2.3.7~7.el5_4.3", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-perl", rpm:"cyrus-imapd-perl~2.3.7~7.el5_4.3", rls:"CentOS5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"cyrus-imapd-utils", rpm:"cyrus-imapd-utils~2.3.7~7.el5_4.3", rls:"CentOS5")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
