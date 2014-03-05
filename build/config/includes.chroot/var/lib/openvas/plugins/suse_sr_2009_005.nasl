# OpenVAS Vulnerability Test
# $Id: suse_sr_2009_005.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory SUSE-SR:2009:005
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
advisory SUSE-SR:2009:005.  SuSE Security Summaries are short
on detail when it comes to the names of packages affected by
a particular bug. Because of this, while this test will detect
out of date packages, it cannot tell you what bugs impact
which packages, or vice versa.";

tag_solution = "Update all out of date packages.";
                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(63469);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-02 19:11:09 +0100 (Mon, 02 Mar 2009)");
 script_cve_id("CVE-2007-0062", "CVE-2008-5078", "CVE-2008-5138", "CVE-2009-0021", "CVE-2009-0040", "CVE-2009-0049", "CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397", "CVE-2009-0478", "CVE-2009-0599", "CVE-2009-0600", "CVE-2009-0601");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("SuSE Security Summary SUSE-SR:2009:005");


 script_description(desc);

 script_summary("SuSE Security Advisory SUSE-SR:2009:005");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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
if ((res = isrpmvuln(pkg:"eID-belgium", rpm:"eID-belgium~2.6.0~73.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~9.0.159.0~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good", rpm:"gstreamer-0_10-plugins-good~0.10.7~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-doc", rpm:"gstreamer-0_10-plugins-good-doc~0.10.7~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-extra", rpm:"gstreamer-0_10-plugins-good-extra~0.10.7~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-lang", rpm:"gstreamer-0_10-plugins-good-lang~0.10.7~38.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"keyutils", rpm:"keyutils~1.2~80.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"keyutils-devel", rpm:"keyutils-devel~1.2~80.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"keyutils-libs", rpm:"keyutils-libs~1.2~80.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.26~14.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng3", rpm:"libpng3~1.2.26~14.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng12-0", rpm:"libpng12-0~1.2.26~14.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nagios", rpm:"nagios~3.0.6~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nagios-devel", rpm:"nagios-devel~3.0.6~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nagios-www", rpm:"nagios-www~3.0.6~1.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.4p4~44.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.4p4~44.2", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pam_mount", rpm:"pam_mount~0.35~15.8", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.0~17.9", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.0.0~17.9", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"eID-belgium", rpm:"eID-belgium~2.5.9~119.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~9.0.159.0~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-good", rpm:"gstreamer010-plugins-good~0.10.6~41.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-good-doc", rpm:"gstreamer010-plugins-good-doc~0.10.6~41.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer010-plugins-good-extra", rpm:"gstreamer010-plugins-good-extra~0.10.6~41.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.18~15.10", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.18~15.10", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pam_mount", rpm:"pam_mount~0.18~84.4", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~0.99.6~31.15", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~0.99.6~31.15", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xntp", rpm:"xntp~4.2.4p3~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xntp-doc", rpm:"xntp-doc~4.2.4p3~25.2", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
