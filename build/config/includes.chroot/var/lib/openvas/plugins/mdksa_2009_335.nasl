# OpenVAS Vulnerability Test
# $Id: mdksa_2009_335.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:335 (ffmpeg)
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
tag_insight = "A vulnerability was discovered and corrected in ffmpeg:

MPlayer allows remote attackers to cause a denial of service
(application crash) via (1) a malformed AAC file, as demonstrated
by lol-vlc.aac; or (2) a malformed Ogg Media (OGM) file, as
demonstrated by lol-ffplay.ogm, different vectors than CVE-2007-6718
(CVE-2008-4610).

Packages for 2008.0 are being provided due to extended support for
Corporate products.

This update provides a solution to this vulnerability.

Affected: 2008.0, 2009.0, Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:335";
tag_summary = "The remote host is missing an update to ffmpeg
announced via advisory MDVSA-2009:335.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66545);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
 script_cve_id("CVE-2007-6718", "CVE-2008-4610");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Mandriva Security Advisory MDVSA-2009:335 (ffmpeg)");


 script_description(desc);

 script_summary("Mandriva Security Advisory MDVSA-2009:335 (ffmpeg)");

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
if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~0.4.9~3.pre1.8994.2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavformats51", rpm:"libavformats51~0.4.9~3.pre1.8994.2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavutil49", rpm:"libavutil49~0.4.9~3.pre1.8994.2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg51", rpm:"libffmpeg51~0.4.9~3.pre1.8994.2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg51-devel", rpm:"libffmpeg51-devel~0.4.9~3.pre1.8994.2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg51-static-devel", rpm:"libffmpeg51-static-devel~0.4.9~3.pre1.8994.2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avformats51", rpm:"lib64avformats51~0.4.9~3.pre1.8994.2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avutil49", rpm:"lib64avutil49~0.4.9~3.pre1.8994.2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg51", rpm:"lib64ffmpeg51~0.4.9~3.pre1.8994.2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg51-devel", rpm:"lib64ffmpeg51-devel~0.4.9~3.pre1.8994.2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg51-static-devel", rpm:"lib64ffmpeg51-static-devel~0.4.9~3.pre1.8994.2.4mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavformats52", rpm:"libavformats52~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavutil49", rpm:"libavutil49~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg51", rpm:"libffmpeg51~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libswscaler0", rpm:"libswscaler0~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avformats52", rpm:"lib64avformats52~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avutil49", rpm:"lib64avutil49~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg51", rpm:"lib64ffmpeg51~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64swscaler0", rpm:"lib64swscaler0~0.4.9~3.pre1.14161.1.3mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavformats52", rpm:"libavformats52~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavutil49", rpm:"libavutil49~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg51", rpm:"libffmpeg51~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libswscaler0", rpm:"libswscaler0~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avformats52", rpm:"lib64avformats52~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avutil49", rpm:"lib64avutil49~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg51", rpm:"lib64ffmpeg51~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64swscaler0", rpm:"lib64swscaler0~0.4.9~3.pre1.14161.1.3mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
