# OpenVAS Vulnerability Test
# $Id: suse_sa_2009_019.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory SUSE-SA:2009:019 (krb5)
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
tag_insight = "The Kerberos implementation from MIT is vulnerable to four
different security issues that range from a remote crash to
to possible, but very unlikely, remote code execution.
- CVE-2009-0844: The SPNEGO GSS-API implementation can read
beyond the end of a buffer (network input) which leads to a
crash.
- CVE-2009-0845: A NULL pointer dereference in the SPNEGO code
can lead to a crash which affects programs using the GSS-API.
- CVE-2009-0846: The ASN.1 decoder can free an uninitialized NULL
pointer which leads to a crash and can possibly lead to remote
code execution. This bug can be exploited before any authen-
tication happened,
- CVE-2009-0847: The ASN.1 decoder incorrectly validates a length
parameter which leads to malloc() errors any possibly to a crash.";
tag_solution = "Update your system with the packages as indicated in
the referenced security advisory.

https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:019";
tag_summary = "The remote host is missing updates announced in
advisory SUSE-SA:2009:019.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63799);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
 script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("SuSE Security Advisory SUSE-SA:2009:019 (krb5)");


 script_description(desc);

 script_summary("SuSE Security Advisory SUSE-SA:2009:019 (krb5)");

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
if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.2~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.2~22.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.2~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.2~22.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.2~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.2~22.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.2~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.2~22.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.2~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.2~22.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.2~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.2~22.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debuginfo-64bit", rpm:"krb5-debuginfo-64bit~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.2~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.2~22.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.2~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.2~22.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-debuginfo-32bit", rpm:"krb5-debuginfo-32bit~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.3~132.3.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.3~132.5.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.3~50.3", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.3~50.5", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.2~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.2~22.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.2~22.7", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.2~22.9", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
