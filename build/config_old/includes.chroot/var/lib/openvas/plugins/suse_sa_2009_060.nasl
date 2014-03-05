# OpenVAS Vulnerability Test
# $Id: suse_sa_2009_060.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory SUSE-SA:2009:060 (kernel)
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
tag_insight = "The SUSE Linux Enterprise 11 and openSUSE 11.1 Kernel was updated to
2.6.27.39 fixing various bugs and security issues.

For details, please visit the referenced security advisories.

A complete list of changes can be found in the RPM changelog.";
tag_solution = "Update your system with the packages as indicated in
the referenced security advisory.

https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:060";
tag_summary = "The remote host is missing updates announced in
advisory SUSE-SA:2009:060.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66460);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_cve_id("CVE-2005-4881", "CVE-2009-2903", "CVE-2009-2910", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3726");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("SuSE Security Advisory SUSE-SA:2009:060 (kernel)");


 script_description(desc);

 script_summary("SuSE Security Advisory SUSE-SA:2009:060 (kernel)");

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
if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae-debuginfo", rpm:"kernel-pae-debuginfo~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae-debugsource", rpm:"kernel-pae-debugsource~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source-debuginfo", rpm:"kernel-source-debuginfo~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-trace-debuginfo", rpm:"kernel-trace-debuginfo~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-trace-debugsource", rpm:"kernel-trace-debugsource~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-extra", rpm:"kernel-debug-extra~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~2.6.3~3.13.66", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump-debuginfo", rpm:"kernel-kdump-debuginfo~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump-debugsource", rpm:"kernel-kdump-debugsource~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-ppc64-debuginfo", rpm:"kernel-ppc64-debuginfo~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-ppc64-debugsource", rpm:"kernel-ppc64-debugsource~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-ps3-debuginfo", rpm:"kernel-ps3-debuginfo~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-ps3-debugsource", rpm:"kernel-ps3-debugsource~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-ps3", rpm:"kernel-ps3~2.6.27.39~0.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
