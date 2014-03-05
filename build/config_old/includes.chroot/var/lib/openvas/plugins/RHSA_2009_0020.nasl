# OpenVAS Vulnerability Test
# $Id: RHSA_2009_0020.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory RHSA-2009:0020 ()
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
tag_summary = "The remote host is missing updates announced in
advisory RHSA-2009:0020.

A flaw was discovered in the way BIND checked the return value of the
OpenSSL DSA_do_verify function. On systems using DNSSEC, a malicious zone
could present a malformed DSA certificate and bypass proper certificate
validation, allowing spoofing attacks. (CVE-2009-0025)

For users of Red Hat Enterprise Linux 3 this update also addresses a bug
which can cause BIND to occasionally exit with an assertion failure.

All BIND users are advised to upgrade to the updated package, which
contains a backported patch to resolve this issue. After installing the
update, BIND daemon will be restarted automatically.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if(description)
{
 script_id(63133);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
 script_cve_id("CVE-2009-0025");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("RedHat Security Advisory RHSA-2009:0020");


 script_description(desc);

 script_summary("Redhat Security Advisory RHSA-2009:0020");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-0020.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#moderate");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.2.1~11.el2", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.2.1~11.el2", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.2.1~11.el2", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.2.4~23.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.2.4~23.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.2.4~23.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.2.4~23.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.2.4~23.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.2.4~23.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.2.4~30.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.2.4~30.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.2.4~30.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.2.4~30.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.2.4~30.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.2.4~30.el4_7.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.3.4~6.0.3.P1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.3.4~6.0.3.P1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.3.4~6.0.3.P1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.3.4~6.0.3.P1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.3.4~6.0.3.P1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.3.4~6.0.3.P1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.3.4~6.0.3.P1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libbind-devel", rpm:"bind-libbind-devel~9.3.4~6.0.3.P1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"caching-nameserver", rpm:"caching-nameserver~9.3.4~6.0.3.P1.el5_2", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
