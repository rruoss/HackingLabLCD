# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "A flaw has been discovered in 2.6 series Linux kernels that allows an
attacker to send a malformed TCP packet, causing the affected kernel to
possibly enter an infinite loop and hang the vulnerable machine.";
tag_solution = "Users are encouraged to upgrade to the latest available sources for their
system:

    # emerge sync
    # emerge -pv your-favorite-sources
    # emerge your-favorite-sources

    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200407-12
http://bugs.gentoo.org/show_bug.cgi?id=55694";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200407-12.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(54619);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_bugtraq_id(10634);
 script_cve_id("CVE-2004-0626");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Gentoo Security Advisory GLSA 200407-12 (Kernel)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200407-12 (Kernel)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/gentoo");
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

include("pkg-lib-gentoo.inc");

res = "";
report = "";
if ((res = ispkgvuln(pkg:"sys-kernel/aa-sources", unaffected: make_list("ge 2.6.5-r5", "lt 2.6"), vulnerable: make_list("lt 2.6.5-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ck-sources", unaffected: make_list("ge 2.6.7-r2", "lt 2.6"), vulnerable: make_list("lt 2.6.7-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/development-sources", unaffected: make_list("ge 2.6.8"), vulnerable: make_list("lt 2.6.8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.7-r7"), vulnerable: make_list("lt 2.6.7-r7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hardened-dev-sources", unaffected: make_list("ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hppa-dev-sources", unaffected: make_list("ge 2.6.7_p1-r1"), vulnerable: make_list("lt 2.6.7_p1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mips-sources", unaffected: make_list("ge 2.6.4-r4", "lt 2.6"), vulnerable: make_list("lt 2.6.4-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mm-sources", unaffected: make_list("ge 2.6.7-r4", "lt 2.6"), vulnerable: make_list("lt 2.6.7-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pegasos-dev-sources", unaffected: make_list("ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/rsbac-dev-sources", unaffected: make_list("ge 2.6.7-r1"), vulnerable: make_list("lt 2.6.7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/uclinux-sources", unaffected: make_list("ge 2.6.7_p0-r1", "lt 2.6"), vulnerable: make_list("lt 2.6.7_p0"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/usermode-sources", unaffected: make_list("ge 2.6.6-r2", "lt 2.6"), vulnerable: make_list("lt 2.6.6-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/win4lin-sources", unaffected: make_list("ge 2.6.7-r1", "lt 2.6"), vulnerable: make_list("lt 2.6.7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/xbox-sources", unaffected: make_list("ge 2.6.7-r1", "lt 2.6"), vulnerable: make_list("lt 2.6.7-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
