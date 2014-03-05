# OpenVAS Vulnerability Test
# $Id: suse_sa_2009_059.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory SUSE-SA:2009:059 (bind)
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
tag_insight = "The bind DNS server was updated to close a possible cache poisoning
vulnerability which allowed to bypass DNSSEC.

This problem can only happen after the other spoofing/poisoning
mechanisms have been bypassed already (the port and transaction id
randomization). Also this can only happen if the server is setup for
DNSSEC. Due to this limitation we consider this a minor issue.

The DNSSEC implementation was redone in 2004 and implemented in
bind 9.6.

Earlier bind version do not support the DNSSEC version and so are not
affected.

This means that the Bind versions of SUSE Linux Enterprise Server 9
(bind 9.3.4) and SUSE Linux Enterprise Server 10 (bind 9.3.4) are
not affected by this problem.";
tag_solution = "Update your system with the packages as indicated in
the referenced security advisory.

https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:059";
tag_summary = "The remote host is missing updates announced in
advisory SUSE-SA:2009:059.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66459);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_cve_id("CVE-2009-4022");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("SuSE Security Advisory SUSE-SA:2009:059 (bind)");


 script_description(desc);

 script_summary("SuSE Security Advisory SUSE-SA:2009:059 (bind)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.6.1P2~1.1.1", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.6.1P2~1.1.1", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.6.1P2~1.1.1", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.6.1P2~1.1.1", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.6.1P2~1.1.1", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.6.1P2~1.1.1", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.6.1P2~1.1.1", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.6.1P2~1.1.1", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.5.0P2~18.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.5.0P2~18.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.5.0P2~18.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.5.0P2~18.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.5.0P2~18.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.5.0P2~18.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.5.0P2~18.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.5.0P2~18.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.4.2~39.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.4.2~39.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.4.2~39.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.4.2~39.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.4.2~39.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.4.2~39.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.4.2~39.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.4.2~39.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs-64bit", rpm:"bind-libs-64bit~9.5.0P2~18.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-devel-64bit", rpm:"bind-devel-64bit~9.4.2~39.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs-64bit", rpm:"bind-libs-64bit~9.4.2~39.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs-debuginfo-32bit", rpm:"bind-libs-debuginfo-32bit~9.6.1P2~1.1.1", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.6.1P2~1.1.1", rls:"openSUSE11.2")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.5.0P2~18.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.4.2~39.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}