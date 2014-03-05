# OpenVAS Vulnerability Test
# $Id: mdksa_2009_148.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:148 (kernel)
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
tag_insight = "Some vulnerabilities were discovered and corrected in the Linux
2.6 kernel. For details, please visit the referenced security
advisories.

Additionally, the kernel package was updated to the Linux upstream
stable version 2.6.29.6.

To update your kernel, please follow the directions located at:

http://www.mandriva.com/en/security/kernelupdate

Affected: 2009.1";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:148";
tag_summary = "The remote host is missing an update to kernel
announced via advisory MDVSA-2009:148.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64376);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-15 04:21:35 +0200 (Wed, 15 Jul 2009)");
 script_cve_id("CVE-2009-1389", "CVE-2009-1961", "CVE-2009-1630", "CVE-2009-1385", "CVE-2009-1633");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Mandrake Security Advisory MDVSA-2009:148 (kernel)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:148 (kernel)");

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
if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel-2.6.29.6-desktop-1mnb", rpm:"alsa_raoppcm-kernel-2.6.29.6-desktop-1mnb~0.5.1~2mdv2008.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel-2.6.29.6-desktop586-1mnb", rpm:"alsa_raoppcm-kernel-2.6.29.6-desktop586-1mnb~0.5.1~2mdv2008.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel-2.6.29.6-server-1mnb", rpm:"alsa_raoppcm-kernel-2.6.29.6-server-1mnb~0.5.1~2mdv2008.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel-desktop586-latest", rpm:"alsa_raoppcm-kernel-desktop586-latest~0.5.1~1.20090706.2mdv2008.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel-desktop-latest", rpm:"alsa_raoppcm-kernel-desktop-latest~0.5.1~1.20090706.2mdv2008.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel-server-latest", rpm:"alsa_raoppcm-kernel-server-latest~0.5.1~1.20090706.2mdv2008.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-2.6.29.6-desktop-1mnb", rpm:"broadcom-wl-kernel-2.6.29.6-desktop-1mnb~5.10.79.10~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-2.6.29.6-desktop586-1mnb", rpm:"broadcom-wl-kernel-2.6.29.6-desktop586-1mnb~5.10.79.10~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-2.6.29.6-server-1mnb", rpm:"broadcom-wl-kernel-2.6.29.6-server-1mnb~5.10.79.10~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop586-latest", rpm:"broadcom-wl-kernel-desktop586-latest~5.10.79.10~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop-latest", rpm:"broadcom-wl-kernel-desktop-latest~5.10.79.10~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"broadcom-wl-kernel-server-latest", rpm:"broadcom-wl-kernel-server-latest~5.10.79.10~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"em8300-kernel-2.6.29.6-desktop-1mnb", rpm:"em8300-kernel-2.6.29.6-desktop-1mnb~0.17.2~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"em8300-kernel-2.6.29.6-desktop586-1mnb", rpm:"em8300-kernel-2.6.29.6-desktop586-1mnb~0.17.2~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"em8300-kernel-2.6.29.6-server-1mnb", rpm:"em8300-kernel-2.6.29.6-server-1mnb~0.17.2~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"em8300-kernel-desktop586-latest", rpm:"em8300-kernel-desktop586-latest~0.17.2~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"em8300-kernel-desktop-latest", rpm:"em8300-kernel-desktop-latest~0.17.2~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"em8300-kernel-server-latest", rpm:"em8300-kernel-server-latest~0.17.2~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fcpci-kernel-2.6.29.6-desktop-1mnb", rpm:"fcpci-kernel-2.6.29.6-desktop-1mnb~3.11.07~7mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fcpci-kernel-2.6.29.6-desktop586-1mnb", rpm:"fcpci-kernel-2.6.29.6-desktop586-1mnb~3.11.07~7mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fcpci-kernel-2.6.29.6-server-1mnb", rpm:"fcpci-kernel-2.6.29.6-server-1mnb~3.11.07~7mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fcpci-kernel-desktop586-latest", rpm:"fcpci-kernel-desktop586-latest~3.11.07~1.20090706.7mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fcpci-kernel-desktop-latest", rpm:"fcpci-kernel-desktop-latest~3.11.07~1.20090706.7mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fcpci-kernel-server-latest", rpm:"fcpci-kernel-server-latest~3.11.07~1.20090706.7mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-2.6.29.6-desktop-1mnb", rpm:"fglrx-kernel-2.6.29.6-desktop-1mnb~8.600~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-2.6.29.6-desktop586-1mnb", rpm:"fglrx-kernel-2.6.29.6-desktop586-1mnb~8.600~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-2.6.29.6-server-1mnb", rpm:"fglrx-kernel-2.6.29.6-server-1mnb~8.600~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-desktop586-latest", rpm:"fglrx-kernel-desktop586-latest~8.600~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-desktop-latest", rpm:"fglrx-kernel-desktop-latest~8.600~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fglrx-kernel-server-latest", rpm:"fglrx-kernel-server-latest~8.600~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-2.6.29.6-desktop-1mnb", rpm:"hcfpcimodem-kernel-2.6.29.6-desktop-1mnb~1.18~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-2.6.29.6-desktop586-1mnb", rpm:"hcfpcimodem-kernel-2.6.29.6-desktop586-1mnb~1.18~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-2.6.29.6-server-1mnb", rpm:"hcfpcimodem-kernel-2.6.29.6-server-1mnb~1.18~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-desktop586-latest", rpm:"hcfpcimodem-kernel-desktop586-latest~1.18~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-desktop-latest", rpm:"hcfpcimodem-kernel-desktop-latest~1.18~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hcfpcimodem-kernel-server-latest", rpm:"hcfpcimodem-kernel-server-latest~1.18~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hsfmodem-kernel-2.6.29.6-desktop-1mnb", rpm:"hsfmodem-kernel-2.6.29.6-desktop-1mnb~7.80.02.03~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hsfmodem-kernel-2.6.29.6-desktop586-1mnb", rpm:"hsfmodem-kernel-2.6.29.6-desktop586-1mnb~7.80.02.03~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hsfmodem-kernel-2.6.29.6-server-1mnb", rpm:"hsfmodem-kernel-2.6.29.6-server-1mnb~7.80.02.03~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hsfmodem-kernel-desktop586-latest", rpm:"hsfmodem-kernel-desktop586-latest~7.80.02.03~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hsfmodem-kernel-desktop-latest", rpm:"hsfmodem-kernel-desktop-latest~7.80.02.03~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hsfmodem-kernel-server-latest", rpm:"hsfmodem-kernel-server-latest~7.80.02.03~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hso-kernel-2.6.29.6-desktop-1mnb", rpm:"hso-kernel-2.6.29.6-desktop-1mnb~1.2~3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hso-kernel-2.6.29.6-desktop586-1mnb", rpm:"hso-kernel-2.6.29.6-desktop586-1mnb~1.2~3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hso-kernel-2.6.29.6-server-1mnb", rpm:"hso-kernel-2.6.29.6-server-1mnb~1.2~3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hso-kernel-desktop586-latest", rpm:"hso-kernel-desktop586-latest~1.2~1.20090706.3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hso-kernel-desktop-latest", rpm:"hso-kernel-desktop-latest~1.2~1.20090706.3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"hso-kernel-server-latest", rpm:"hso-kernel-server-latest~1.2~1.20090706.3mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-2.6.29.6-1mnb", rpm:"kernel-2.6.29.6-1mnb~1~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-2.6.29.6-1mnb", rpm:"kernel-desktop-2.6.29.6-1mnb~1~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-2.6.29.6-1mnb", rpm:"kernel-desktop586-2.6.29.6-1mnb~1~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-devel-2.6.29.6-1mnb", rpm:"kernel-desktop586-devel-2.6.29.6-1mnb~1~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~2.6.29.6~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~2.6.29.6~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-devel-2.6.29.6-1mnb", rpm:"kernel-desktop-devel-2.6.29.6-1mnb~1~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~2.6.29.6~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~2.6.29.6~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.29.6~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-2.6.29.6-1mnb", rpm:"kernel-server-2.6.29.6-1mnb~1~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-devel-2.6.29.6-1mnb", rpm:"kernel-server-devel-2.6.29.6-1mnb~1~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~2.6.29.6~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~2.6.29.6~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source-2.6.29.6-1mnb", rpm:"kernel-source-2.6.29.6-1mnb~1~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~2.6.29.6~1mnb2", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-2.6.29.6-desktop-1mnb", rpm:"kqemu-kernel-2.6.29.6-desktop-1mnb~1.4.0pre1~4", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-2.6.29.6-desktop586-1mnb", rpm:"kqemu-kernel-2.6.29.6-desktop586-1mnb~1.4.0pre1~4", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-2.6.29.6-server-1mnb", rpm:"kqemu-kernel-2.6.29.6-server-1mnb~1.4.0pre1~4", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-desktop586-latest", rpm:"kqemu-kernel-desktop586-latest~1.4.0pre1~1.20090706.4", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-desktop-latest", rpm:"kqemu-kernel-desktop-latest~1.4.0pre1~1.20090706.4", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kqemu-kernel-server-latest", rpm:"kqemu-kernel-server-latest~1.4.0pre1~1.20090706.4", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-2.6.29.6-desktop-1mnb", rpm:"libafs-kernel-2.6.29.6-desktop-1mnb~1.4.10~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-2.6.29.6-desktop586-1mnb", rpm:"libafs-kernel-2.6.29.6-desktop586-1mnb~1.4.10~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-2.6.29.6-server-1mnb", rpm:"libafs-kernel-2.6.29.6-server-1mnb~1.4.10~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-desktop586-latest", rpm:"libafs-kernel-desktop586-latest~1.4.10~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-desktop-latest", rpm:"libafs-kernel-desktop-latest~1.4.10~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libafs-kernel-server-latest", rpm:"libafs-kernel-server-latest~1.4.10~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lirc-kernel-2.6.29.6-desktop-1mnb", rpm:"lirc-kernel-2.6.29.6-desktop-1mnb~0.8.5~0.20090320.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lirc-kernel-2.6.29.6-desktop586-1mnb", rpm:"lirc-kernel-2.6.29.6-desktop586-1mnb~0.8.5~0.20090320.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lirc-kernel-2.6.29.6-server-1mnb", rpm:"lirc-kernel-2.6.29.6-server-1mnb~0.8.5~0.20090320.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lirc-kernel-desktop586-latest", rpm:"lirc-kernel-desktop586-latest~0.8.5~1.20090706.0.20090320.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lirc-kernel-desktop-latest", rpm:"lirc-kernel-desktop-latest~0.8.5~1.20090706.0.20090320.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lirc-kernel-server-latest", rpm:"lirc-kernel-server-latest~0.8.5~1.20090706.0.20090320.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lzma-kernel-2.6.29.6-desktop-1mnb", rpm:"lzma-kernel-2.6.29.6-desktop-1mnb~4.43~27.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lzma-kernel-2.6.29.6-desktop586-1mnb", rpm:"lzma-kernel-2.6.29.6-desktop586-1mnb~4.43~27.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lzma-kernel-2.6.29.6-server-1mnb", rpm:"lzma-kernel-2.6.29.6-server-1mnb~4.43~27.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lzma-kernel-desktop586-latest", rpm:"lzma-kernel-desktop586-latest~4.43~1.20090706.27.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lzma-kernel-desktop-latest", rpm:"lzma-kernel-desktop-latest~4.43~1.20090706.27.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lzma-kernel-server-latest", rpm:"lzma-kernel-server-latest~4.43~1.20090706.27.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-2.6.29.6-desktop-1mnb", rpm:"madwifi-kernel-2.6.29.6-desktop-1mnb~0.9.4~4.r3998mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-2.6.29.6-desktop586-1mnb", rpm:"madwifi-kernel-2.6.29.6-desktop586-1mnb~0.9.4~4.r3998mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-2.6.29.6-server-1mnb", rpm:"madwifi-kernel-2.6.29.6-server-1mnb~0.9.4~4.r3998mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-desktop586-latest", rpm:"madwifi-kernel-desktop586-latest~0.9.4~1.20090706.4.r3998mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-desktop-latest", rpm:"madwifi-kernel-desktop-latest~0.9.4~1.20090706.4.r3998mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"madwifi-kernel-server-latest", rpm:"madwifi-kernel-server-latest~0.9.4~1.20090706.4.r3998mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netfilter-rtsp-kernel-2.6.29.6-desktop-1mnb", rpm:"netfilter-rtsp-kernel-2.6.29.6-desktop-1mnb~2.6.26~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netfilter-rtsp-kernel-2.6.29.6-desktop586-1mnb", rpm:"netfilter-rtsp-kernel-2.6.29.6-desktop586-1mnb~2.6.26~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netfilter-rtsp-kernel-2.6.29.6-server-1mnb", rpm:"netfilter-rtsp-kernel-2.6.29.6-server-1mnb~2.6.26~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netfilter-rtsp-kernel-desktop586-latest", rpm:"netfilter-rtsp-kernel-desktop586-latest~2.6.26~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netfilter-rtsp-kernel-desktop-latest", rpm:"netfilter-rtsp-kernel-desktop-latest~2.6.26~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netfilter-rtsp-kernel-server-latest", rpm:"netfilter-rtsp-kernel-server-latest~2.6.26~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kernel-2.6.29.6-desktop-1mnb", rpm:"nouveau-kernel-2.6.29.6-desktop-1mnb~0.0.12~0.20090329.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kernel-2.6.29.6-desktop586-1mnb", rpm:"nouveau-kernel-2.6.29.6-desktop586-1mnb~0.0.12~0.20090329.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kernel-2.6.29.6-server-1mnb", rpm:"nouveau-kernel-2.6.29.6-server-1mnb~0.0.12~0.20090329.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kernel-desktop586-latest", rpm:"nouveau-kernel-desktop586-latest~0.0.12~1.20090706.0.20090329.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kernel-desktop-latest", rpm:"nouveau-kernel-desktop-latest~0.0.12~1.20090706.0.20090329.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nouveau-kernel-server-latest", rpm:"nouveau-kernel-server-latest~0.0.12~1.20090706.0.20090329.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia173-kernel-2.6.29.6-desktop-1mnb", rpm:"nvidia173-kernel-2.6.29.6-desktop-1mnb~173.14.18~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia173-kernel-2.6.29.6-desktop586-1mnb", rpm:"nvidia173-kernel-2.6.29.6-desktop586-1mnb~173.14.18~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia173-kernel-2.6.29.6-server-1mnb", rpm:"nvidia173-kernel-2.6.29.6-server-1mnb~173.14.18~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia173-kernel-desktop586-latest", rpm:"nvidia173-kernel-desktop586-latest~173.14.18~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia173-kernel-desktop-latest", rpm:"nvidia173-kernel-desktop-latest~173.14.18~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia173-kernel-server-latest", rpm:"nvidia173-kernel-server-latest~173.14.18~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-2.6.29.6-desktop-1mnb", rpm:"nvidia96xx-kernel-2.6.29.6-desktop-1mnb~96.43.11~5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-2.6.29.6-desktop586-1mnb", rpm:"nvidia96xx-kernel-2.6.29.6-desktop586-1mnb~96.43.11~5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-2.6.29.6-server-1mnb", rpm:"nvidia96xx-kernel-2.6.29.6-server-1mnb~96.43.11~5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-desktop586-latest", rpm:"nvidia96xx-kernel-desktop586-latest~96.43.11~1.20090706.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-desktop-latest", rpm:"nvidia96xx-kernel-desktop-latest~96.43.11~1.20090706.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-server-latest", rpm:"nvidia96xx-kernel-server-latest~96.43.11~1.20090706.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-2.6.29.6-desktop-1mnb", rpm:"nvidia-current-kernel-2.6.29.6-desktop-1mnb~180.51~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-2.6.29.6-desktop586-1mnb", rpm:"nvidia-current-kernel-2.6.29.6-desktop586-1mnb~180.51~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-2.6.29.6-server-1mnb", rpm:"nvidia-current-kernel-2.6.29.6-server-1mnb~180.51~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~180.51~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~180.51~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~180.51~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opencbm-kernel-2.6.29.6-desktop-1mnb", rpm:"opencbm-kernel-2.6.29.6-desktop-1mnb~0.4.2a~4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opencbm-kernel-2.6.29.6-desktop586-1mnb", rpm:"opencbm-kernel-2.6.29.6-desktop586-1mnb~0.4.2a~4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opencbm-kernel-2.6.29.6-server-1mnb", rpm:"opencbm-kernel-2.6.29.6-server-1mnb~0.4.2a~4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opencbm-kernel-desktop586-latest", rpm:"opencbm-kernel-desktop586-latest~0.4.2a~1.20090706.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opencbm-kernel-desktop-latest", rpm:"opencbm-kernel-desktop-latest~0.4.2a~1.20090706.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"opencbm-kernel-server-latest", rpm:"opencbm-kernel-server-latest~0.4.2a~1.20090706.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rt2870-kernel-2.6.29.6-desktop-1mnb", rpm:"rt2870-kernel-2.6.29.6-desktop-1mnb~1.4.0.0~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rt2870-kernel-2.6.29.6-desktop586-1mnb", rpm:"rt2870-kernel-2.6.29.6-desktop586-1mnb~1.4.0.0~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rt2870-kernel-2.6.29.6-server-1mnb", rpm:"rt2870-kernel-2.6.29.6-server-1mnb~1.4.0.0~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rt2870-kernel-desktop586-latest", rpm:"rt2870-kernel-desktop586-latest~1.4.0.0~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rt2870-kernel-desktop-latest", rpm:"rt2870-kernel-desktop-latest~1.4.0.0~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rt2870-kernel-server-latest", rpm:"rt2870-kernel-server-latest~1.4.0.0~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"slmodem-kernel-2.6.29.6-desktop-1mnb", rpm:"slmodem-kernel-2.6.29.6-desktop-1mnb~2.9.11~0.20080817.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"slmodem-kernel-2.6.29.6-desktop586-1mnb", rpm:"slmodem-kernel-2.6.29.6-desktop586-1mnb~2.9.11~0.20080817.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"slmodem-kernel-2.6.29.6-server-1mnb", rpm:"slmodem-kernel-2.6.29.6-server-1mnb~2.9.11~0.20080817.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"slmodem-kernel-desktop586-latest", rpm:"slmodem-kernel-desktop586-latest~2.9.11~1.20090706.0.20080817.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"slmodem-kernel-desktop-latest", rpm:"slmodem-kernel-desktop-latest~2.9.11~1.20090706.0.20080817.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"slmodem-kernel-server-latest", rpm:"slmodem-kernel-server-latest~2.9.11~1.20090706.0.20080817.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-kernel-2.6.29.6-desktop-1mnb", rpm:"squashfs-kernel-2.6.29.6-desktop-1mnb~3.4~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-kernel-2.6.29.6-desktop586-1mnb", rpm:"squashfs-kernel-2.6.29.6-desktop586-1mnb~3.4~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-kernel-2.6.29.6-server-1mnb", rpm:"squashfs-kernel-2.6.29.6-server-1mnb~3.4~1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-kernel-desktop586-latest", rpm:"squashfs-kernel-desktop586-latest~3.4~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-kernel-desktop-latest", rpm:"squashfs-kernel-desktop-latest~3.4~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-kernel-server-latest", rpm:"squashfs-kernel-server-latest~3.4~1.20090706.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-2.6.29.6-desktop-1mnb", rpm:"squashfs-lzma-kernel-2.6.29.6-desktop-1mnb~3.3~10mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-2.6.29.6-desktop586-1mnb", rpm:"squashfs-lzma-kernel-2.6.29.6-desktop586-1mnb~3.3~10mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-2.6.29.6-server-1mnb", rpm:"squashfs-lzma-kernel-2.6.29.6-server-1mnb~3.3~10mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-desktop586-latest", rpm:"squashfs-lzma-kernel-desktop586-latest~3.3~1.20090706.10mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-desktop-latest", rpm:"squashfs-lzma-kernel-desktop-latest~3.3~1.20090706.10mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-server-latest", rpm:"squashfs-lzma-kernel-server-latest~3.3~1.20090706.10mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"syntek-kernel-2.6.29.6-desktop-1mnb", rpm:"syntek-kernel-2.6.29.6-desktop-1mnb~1.3.1~5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"syntek-kernel-2.6.29.6-desktop586-1mnb", rpm:"syntek-kernel-2.6.29.6-desktop586-1mnb~1.3.1~5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"syntek-kernel-2.6.29.6-server-1mnb", rpm:"syntek-kernel-2.6.29.6-server-1mnb~1.3.1~5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"syntek-kernel-desktop586-latest", rpm:"syntek-kernel-desktop586-latest~1.3.1~1.20090706.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"syntek-kernel-desktop-latest", rpm:"syntek-kernel-desktop-latest~1.3.1~1.20090706.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"syntek-kernel-server-latest", rpm:"syntek-kernel-server-latest~1.3.1~1.20090706.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tp_smapi-kernel-2.6.29.6-desktop-1mnb", rpm:"tp_smapi-kernel-2.6.29.6-desktop-1mnb~0.40~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tp_smapi-kernel-2.6.29.6-desktop586-1mnb", rpm:"tp_smapi-kernel-2.6.29.6-desktop586-1mnb~0.40~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tp_smapi-kernel-2.6.29.6-server-1mnb", rpm:"tp_smapi-kernel-2.6.29.6-server-1mnb~0.40~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tp_smapi-kernel-desktop586-latest", rpm:"tp_smapi-kernel-desktop586-latest~0.40~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tp_smapi-kernel-desktop-latest", rpm:"tp_smapi-kernel-desktop-latest~0.40~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tp_smapi-kernel-server-latest", rpm:"tp_smapi-kernel-server-latest~0.40~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vboxadditions-kernel-2.6.29.6-desktop-1mnb", rpm:"vboxadditions-kernel-2.6.29.6-desktop-1mnb~2.2.0~4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vboxadditions-kernel-2.6.29.6-desktop586-1mnb", rpm:"vboxadditions-kernel-2.6.29.6-desktop586-1mnb~2.2.0~4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vboxadditions-kernel-2.6.29.6-server-1mnb", rpm:"vboxadditions-kernel-2.6.29.6-server-1mnb~2.2.0~4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~2.2.0~1.20090706.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~2.2.0~1.20090706.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~2.2.0~1.20090706.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vhba-kernel-2.6.29.6-desktop-1mnb", rpm:"vhba-kernel-2.6.29.6-desktop-1mnb~1.2.1~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vhba-kernel-2.6.29.6-desktop586-1mnb", rpm:"vhba-kernel-2.6.29.6-desktop586-1mnb~1.2.1~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vhba-kernel-2.6.29.6-server-1mnb", rpm:"vhba-kernel-2.6.29.6-server-1mnb~1.2.1~2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vhba-kernel-desktop586-latest", rpm:"vhba-kernel-desktop586-latest~1.2.1~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vhba-kernel-desktop-latest", rpm:"vhba-kernel-desktop-latest~1.2.1~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vhba-kernel-server-latest", rpm:"vhba-kernel-server-latest~1.2.1~1.20090706.2mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-kernel-2.6.29.6-desktop-1mnb", rpm:"virtualbox-kernel-2.6.29.6-desktop-1mnb~2.2.0~4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-kernel-2.6.29.6-desktop586-1mnb", rpm:"virtualbox-kernel-2.6.29.6-desktop586-1mnb~2.2.0~4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-kernel-2.6.29.6-server-1mnb", rpm:"virtualbox-kernel-2.6.29.6-server-1mnb~2.2.0~4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~2.2.0~1.20090706.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~2.2.0~1.20090706.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~2.2.0~1.20090706.4mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-2.6.29.6-desktop-1mnb", rpm:"vpnclient-kernel-2.6.29.6-desktop-1mnb~4.8.01.0640~3mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-2.6.29.6-desktop586-1mnb", rpm:"vpnclient-kernel-2.6.29.6-desktop586-1mnb~4.8.01.0640~3mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-2.6.29.6-server-1mnb", rpm:"vpnclient-kernel-2.6.29.6-server-1mnb~4.8.01.0640~3mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-desktop586-latest", rpm:"vpnclient-kernel-desktop586-latest~4.8.01.0640~1.20090706.3mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-desktop-latest", rpm:"vpnclient-kernel-desktop-latest~4.8.01.0640~1.20090706.3mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"vpnclient-kernel-server-latest", rpm:"vpnclient-kernel-server-latest~4.8.01.0640~1.20090706.3mdv2009.0", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
