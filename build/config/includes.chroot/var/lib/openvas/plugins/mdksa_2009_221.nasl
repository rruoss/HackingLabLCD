# OpenVAS Vulnerability Test
# $Id: mdksa_2009_221.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:221 (libneon0.27)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in libneon0.27:

neon before 0.28.6, when expat is used, does not properly detect
recursion during entity expansion, which allows context-dependent
attackers to cause a denial of service (memory and CPU consumption)
via a crafted XML document containing a large number of nested entity
references, a similar issue to CVE-2003-1564 (CVE-2009-2473).

neon before 0.28.6, when OpenSSL is used, does not properly handle a
'\0' (NUL) character in a domain name in the subject's Common Name
(CN) field of an X.509 certificate, which allows man-in-the-middle
attackers to spoof arbitrary SSL servers via a crafted certificate
issued by a legitimate Certification Authority, a related issue to
CVE-2009-2408 (CVE-2009-2474).

This update provides a solution to these vulnerabilities.

Affected: 2008.1, 2009.0, 2009.1, Corporate 4.0, Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:221";
tag_summary = "The remote host is missing an update to libneon0.27
announced via advisory MDVSA-2009:221.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64693);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2003-1564", "CVE-2009-2473", "CVE-2009-2408", "CVE-2009-2474");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Mandrake Security Advisory MDVSA-2009:221 (libneon0.27)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:221 (libneon0.27)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"libneon0.27", rpm:"libneon0.27~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-devel", rpm:"libneon0.27-devel~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-static-devel", rpm:"libneon0.27-static-devel~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27", rpm:"lib64neon0.27~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-devel", rpm:"lib64neon0.27-devel~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-static-devel", rpm:"lib64neon0.27-static-devel~0.28.3~0.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27", rpm:"libneon0.27~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-devel", rpm:"libneon0.27-devel~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-static-devel", rpm:"libneon0.27-static-devel~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27", rpm:"lib64neon0.27~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-devel", rpm:"lib64neon0.27-devel~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-static-devel", rpm:"lib64neon0.27-static-devel~0.28.3~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27", rpm:"libneon0.27~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-devel", rpm:"libneon0.27-devel~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-static-devel", rpm:"libneon0.27-static-devel~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27", rpm:"lib64neon0.27~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-devel", rpm:"lib64neon0.27-devel~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-static-devel", rpm:"lib64neon0.27-static-devel~0.28.3~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27", rpm:"libneon0.27~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-devel", rpm:"libneon0.27-devel~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-static-devel", rpm:"libneon0.27-static-devel~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27", rpm:"lib64neon0.27~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-devel", rpm:"lib64neon0.27-devel~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-static-devel", rpm:"lib64neon0.27-static-devel~0.28.3~0.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27", rpm:"libneon0.27~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-devel", rpm:"libneon0.27-devel~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libneon0.27-static-devel", rpm:"libneon0.27-static-devel~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27", rpm:"lib64neon0.27~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-devel", rpm:"lib64neon0.27-devel~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64neon0.27-static-devel", rpm:"lib64neon0.27-static-devel~0.28.3~1.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
