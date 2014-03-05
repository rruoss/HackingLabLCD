# OpenVAS Vulnerability Test
# $Id: mdksa_2009_124_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:124-1 (apache)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in apache:

Memory leak in the zlib_stateful_init function in crypto/comp/c_zlib.c
in libssl in OpenSSL 0.9.8f through 0.9.8h allows remote attackers to
cause a denial of service (memory consumption) via multiple calls, as
demonstrated by initial SSL client handshakes to the Apache HTTP Server
mod_ssl that specify a compression algorithm (CVE-2008-1678). Note
that this security issue does not really apply as zlib compression
is not enabled in the openssl build provided by Mandriva, but apache
is patched to address this issue anyway (concerns 2008.1 only).

Cross-site scripting (XSS) vulnerability in proxy_ftp.c in the
mod_proxy_ftp module in Apache 2.0.63 and earlier, and mod_proxy_ftp.c
in the mod_proxy_ftp module in Apache 2.2.9 and earlier 2.2 versions,
allows remote attackers to inject arbitrary web script or HTML via
wildcards in a pathname in an FTP URI (CVE-2008-2939). Note that this
security issue was initially addressed with MDVSA-2008:195 but the
patch fixing the issue was added but not applied in 2009.0.

The Apache HTTP Server 2.2.11 and earlier 2.2 versions does not
properly handle Options=IncludesNOEXEC in the AllowOverride directive,
which allows local users to gain privileges by configuring (1) Options
Includes, (2) Options +Includes, or (3) Options +IncludesNOEXEC in a
.htaccess file, and then inserting an exec element in a .shtml file
(CVE-2009-1195).

This update provides fixes for these vulnerabilities.

Update:

The patch for fixing CVE-2009-1195 for Mandriva Linux 2008.1 was
incomplete, this update addresses the problem.

Affected: 2008.1";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:124-1";
tag_summary = "The remote host is missing an update to apache
announced via advisory MDVSA-2009:124-1.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64377);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-15 04:21:35 +0200 (Wed, 15 Jul 2009)");
 script_cve_id("CVE-2008-1678", "CVE-2008-2939", "CVE-2009-1195");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Mandrake Security Advisory MDVSA-2009:124-1 (apache)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:124-1 (apache)");

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
if ((res = isrpmvuln(pkg:"apache-base", rpm:"apache-base~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_authn_dbd", rpm:"apache-mod_authn_dbd~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_deflate", rpm:"apache-mod_deflate~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_disk_cache", rpm:"apache-mod_disk_cache~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_file_cache", rpm:"apache-mod_file_cache~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_mem_cache", rpm:"apache-mod_mem_cache~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy_ajp", rpm:"apache-mod_proxy_ajp~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-modules", rpm:"apache-modules~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-event", rpm:"apache-mpm-event~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-itk", rpm:"apache-mpm-itk~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-prefork", rpm:"apache-mpm-prefork~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-worker", rpm:"apache-mpm-worker~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-source", rpm:"apache-source~2.2.8~6.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
