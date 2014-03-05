#
#VID slesp2-kernel-6632
# OpenVAS Vulnerability Test
# $
# Description: Security update for Linux kernel
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_summary = "The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    kernel-bigsmp
    kernel-debug
    kernel-default
    kernel-kdump
    kernel-smp
    kernel-source
    kernel-syms
    kernel-vmi
    kernel-vmipae
    kernel-xen
    kernel-xenpae


More details may also be found by searching for the SuSE
Enterprise Server 10 patch database located at
http://download.novell.com/patch/finder/";

tag_solution = "Please install the updates provided by SuSE.";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(66280);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
 script_cve_id("CVE-2009-3547", "CVE-2009-2910", "CVE-2009-3238", "CVE-2009-1192", "CVE-2009-2909", "CVE-2009-2848", "CVE-2009-3002", "CVE-2009-1633");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_name("SLES10: Security update for Linux kernel");


 script_description(desc);

 script_summary("SLES10: Security update for Linux kernel");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:suse:linux_enterprise_server", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.42.7", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.60~0.42.7", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.42.7", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.60~0.42.7", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.42.7", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.42.7", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.42.7", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.16.60~0.42.7", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-vmipae", rpm:"kernel-vmipae~2.6.16.60~0.42.7", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.42.7", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.42.7", rls:"SLES10.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
