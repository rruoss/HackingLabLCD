# OpenVAS Vulnerability Test
# $Id: mdksa_2009_152.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:152 (pulseaudio)
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
tag_insight = "A vulnerability has been found and corrected in pulseaudio:

Tavis Ormandy and Julien Tinnes of the Google Security Team discovered
that pulseaudio, when installed setuid root, does not drop privileges
before re-executing itself to achieve immediate bindings. This can
be exploited by a user who has write access to any directory on the
file system containing /usr/bin to gain local root access. The user
needs to exploit a race condition related to creating a hard link
(CVE-2009-1894).

This update provides fixes for this vulnerability.

Affected: 2008.1, 2009.0, 2009.1";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:152";
tag_summary = "The remote host is missing an update to pulseaudio
announced via advisory MDVSA-2009:152.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64394);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-1894");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Mandrake Security Advisory MDVSA-2009:152 (pulseaudio)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:152 (pulseaudio)");

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
if ((res = isrpmvuln(pkg:"libpulseaudio0", rpm:"libpulseaudio0~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulseaudio-devel", rpm:"libpulseaudio-devel~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulsecore5", rpm:"libpulsecore5~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulseglib20", rpm:"libpulseglib20~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulsezeroconf0", rpm:"libpulsezeroconf0~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio", rpm:"pulseaudio~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-esound-compat", rpm:"pulseaudio-esound-compat~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-bluetooth", rpm:"pulseaudio-module-bluetooth~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-gconf", rpm:"pulseaudio-module-gconf~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-jack", rpm:"pulseaudio-module-jack~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-lirc", rpm:"pulseaudio-module-lirc~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-x11", rpm:"pulseaudio-module-x11~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-zeroconf", rpm:"pulseaudio-module-zeroconf~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-utils", rpm:"pulseaudio-utils~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulseaudio0", rpm:"lib64pulseaudio0~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulseaudio-devel", rpm:"lib64pulseaudio-devel~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulsecore5", rpm:"lib64pulsecore5~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulseglib20", rpm:"lib64pulseglib20~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulsezeroconf0", rpm:"lib64pulsezeroconf0~0.9.9~7.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulseaudio0", rpm:"libpulseaudio0~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulseaudio-devel", rpm:"libpulseaudio-devel~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulsecore5", rpm:"libpulsecore5~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulseglib20", rpm:"libpulseglib20~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulsezeroconf0", rpm:"libpulsezeroconf0~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio", rpm:"pulseaudio~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-esound-compat", rpm:"pulseaudio-esound-compat~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-bluetooth", rpm:"pulseaudio-module-bluetooth~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-gconf", rpm:"pulseaudio-module-gconf~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-jack", rpm:"pulseaudio-module-jack~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-lirc", rpm:"pulseaudio-module-lirc~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-x11", rpm:"pulseaudio-module-x11~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-zeroconf", rpm:"pulseaudio-module-zeroconf~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-utils", rpm:"pulseaudio-utils~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulseaudio0", rpm:"lib64pulseaudio0~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulseaudio-devel", rpm:"lib64pulseaudio-devel~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulsecore5", rpm:"lib64pulsecore5~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulseglib20", rpm:"lib64pulseglib20~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulsezeroconf0", rpm:"lib64pulsezeroconf0~0.9.10~11.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulseaudio0", rpm:"libpulseaudio0~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulseaudio-devel", rpm:"libpulseaudio-devel~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulseglib20", rpm:"libpulseglib20~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpulsezeroconf0", rpm:"libpulsezeroconf0~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio", rpm:"pulseaudio~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-esound-compat", rpm:"pulseaudio-esound-compat~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-bluetooth", rpm:"pulseaudio-module-bluetooth~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-gconf", rpm:"pulseaudio-module-gconf~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-jack", rpm:"pulseaudio-module-jack~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-lirc", rpm:"pulseaudio-module-lirc~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-x11", rpm:"pulseaudio-module-x11~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-module-zeroconf", rpm:"pulseaudio-module-zeroconf~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pulseaudio-utils", rpm:"pulseaudio-utils~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulseaudio0", rpm:"lib64pulseaudio0~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulseaudio-devel", rpm:"lib64pulseaudio-devel~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulseglib20", rpm:"lib64pulseglib20~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pulsezeroconf0", rpm:"lib64pulsezeroconf0~0.9.15~2.0.6mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
