# OpenVAS Vulnerability Test
# $Id: suse_sa_2009_050.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory SUSE-SA:2009:050 (apache2,libapr1)
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
tag_insight = "The Apache web server was updated to fix various security issues:
- the option IncludesNOEXEC could be bypassed via .htaccess (CVE-2009-1195)
- mod_proxy could run into an infinite loop when used as reverse  proxy
(CVE-2009-1890)
- mod_deflate continued to compress large files even after a network
connection was closed, causing mod_deflate to consume large amounts
of CPU (CVE-2009-1891)
- The ap_proxy_ftp_handler function in modules/proxy/proxy_ftp.c in
the mod_proxy_ftp module allows remote FTP servers to cause a denial
of service (NULL pointer dereference and child process crash) via a
malformed reply to an EPSV command. (CVE-2009-3094)
- access restriction bypass in mod_proxy_ftp module (CVE-2009-3095)

Also the libapr1 and libapr-util1 Apache helper libraries were updated
to fix multiple integer overflows that could probably be used to
execute arbitrary code remotely. (CVE-2009-2412)";
tag_solution = "Update your system with the packages as indicated in
the referenced security advisory.

https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:050";
tag_summary = "The remote host is missing updates announced in
advisory SUSE-SA:2009:050.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66106);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
 script_cve_id("CVE-2009-1195", "CVE-2009-1890", "CVE-2009-1891", "CVE-2009-2412", "CVE-2009-3094", "CVE-2009-3095");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("SuSE Security Advisory SUSE-SA:2009:050 (apache2,libapr1)");


 script_description(desc);

 script_summary("SuSE Security Advisory SUSE-SA:2009:050 (apache2,libapr1)");

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
if ((res = isrpmvuln(pkg:"apache2-debuginfo", rpm:"apache2-debuginfo~2.2.10~2.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-debugsource", rpm:"apache2-debugsource~2.2.10~2.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-debuginfo", rpm:"libapr-util1-debuginfo~1.3.4~13.3.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-debugsource", rpm:"libapr-util1-debugsource~1.3.4~13.3.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1-debuginfo", rpm:"libapr1-debuginfo~1.3.3~12.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1-debugsource", rpm:"libapr1-debugsource~1.3.3~12.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.2.10~2.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-devel", rpm:"apache2-devel~2.2.10~2.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.2.10~2.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.2.10~2.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.2.10~2.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.2.10~2.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.2.10~2.8.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1", rpm:"libapr-util1~1.3.4~13.3.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-dbd-mysql", rpm:"libapr-util1-dbd-mysql~1.3.4~13.3.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-dbd-pgsql", rpm:"libapr-util1-dbd-pgsql~1.3.4~13.3.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-dbd-sqlite3", rpm:"libapr-util1-dbd-sqlite3~1.3.4~13.3.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-devel", rpm:"libapr-util1-devel~1.3.4~13.3.2", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1", rpm:"libapr1~1.3.3~12.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1-devel", rpm:"libapr1-devel~1.3.3~12.2.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-debuginfo", rpm:"apache2-debuginfo~2.2.8~28.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-debugsource", rpm:"apache2-debugsource~2.2.8~28.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-debuginfo", rpm:"libapr-util1-debuginfo~1.2.12~43.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-debugsource", rpm:"libapr-util1-debugsource~1.2.12~43.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1-debuginfo", rpm:"libapr1-debuginfo~1.2.12~27.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1-debugsource", rpm:"libapr1-debugsource~1.2.12~27.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.2.8~28.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-devel", rpm:"apache2-devel~2.2.8~28.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.2.8~28.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.2.8~28.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.2.8~28.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.2.8~28.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.2.8~28.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1", rpm:"libapr-util1~1.2.12~43.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-dbd-mysql", rpm:"libapr-util1-dbd-mysql~1.2.12~43.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-dbd-pgsql", rpm:"libapr-util1-dbd-pgsql~1.2.12~43.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-dbd-sqlite3", rpm:"libapr-util1-dbd-sqlite3~1.2.12~43.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-devel", rpm:"libapr-util1-devel~1.2.12~43.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1", rpm:"libapr1~1.2.12~27.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1-devel", rpm:"libapr1-devel~1.2.12~27.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.2.4~70.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-devel", rpm:"apache2-devel~2.2.4~70.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.2.4~70.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.2.4~70.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.2.4~70.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.2.4~70.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.2.4~70.11", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1", rpm:"libapr-util1~1.2.8~68.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-dbd-mysql", rpm:"libapr-util1-dbd-mysql~1.2.8~68.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-dbd-pgsql", rpm:"libapr-util1-dbd-pgsql~1.2.8~68.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-dbd-sqlite3", rpm:"libapr-util1-dbd-sqlite3~1.2.8~68.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-devel", rpm:"libapr-util1-devel~1.2.8~68.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1", rpm:"libapr1~1.2.9~9.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1-devel", rpm:"libapr1-devel~1.2.9~9.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-64bit", rpm:"libapr-util1-64bit~1.2.12~43.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-devel-64bit", rpm:"libapr-util1-devel-64bit~1.2.12~43.4", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1-64bit", rpm:"libapr1-64bit~1.2.12~27.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1-devel-64bit", rpm:"libapr1-devel-64bit~1.2.12~27.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-64bit", rpm:"libapr-util1-64bit~1.2.8~68.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr-util1-devel-64bit", rpm:"libapr-util1-devel-64bit~1.2.8~68.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1-64bit", rpm:"libapr1-64bit~1.2.9~9.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr1-devel-64bit", rpm:"libapr1-devel-64bit~1.2.9~9.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
