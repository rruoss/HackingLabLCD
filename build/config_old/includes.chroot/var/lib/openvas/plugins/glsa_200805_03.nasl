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
tag_insight = "A vulnerability was found in aterm, Eterm, Mrxvt, multi-aterm, RXVT,
rxvt-unicode, and wterm, allowing for local privilege escalation.";
tag_solution = "All aterm users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/aterm-1.0.1-r1'

All Eterm users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/eterm-0.9.4-r1'

All Mrxvt users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/mrxvt-0.5.3-r2'

All multi-aterm users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/multi-aterm-0.2.1-r1'

All RXVT users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/rxvt-2.7.10-r4'

All rxvt-unicode users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/rxvt-unicode-9.02-r1'

All wterm users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/wterm-6.2.9-r3'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200805-03
http://bugs.gentoo.org/show_bug.cgi?id=216833
http://bugs.gentoo.org/show_bug.cgi?id=217819
http://bugs.gentoo.org/show_bug.cgi?id=219746
http://bugs.gentoo.org/show_bug.cgi?id=219750
http://bugs.gentoo.org/show_bug.cgi?id=219754
http://bugs.gentoo.org/show_bug.cgi?id=219760
http://bugs.gentoo.org/show_bug.cgi?id=219762";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200805-03.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(60941);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2008-1142", "CVE-2008-1692");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Gentoo Security Advisory GLSA 200805-03 (aterm eterm rxvt mrxvt multi-aterm wterm rxvt-unicode)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200805-03 (aterm eterm rxvt mrxvt multi-aterm wterm rxvt-unicode)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = ispkgvuln(pkg:"x11-terms/aterm", unaffected: make_list("ge 1.0.1-r1"), vulnerable: make_list("lt 1.0.1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/eterm", unaffected: make_list("ge 0.9.4-r1"), vulnerable: make_list("lt 0.9.4-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/mrxvt", unaffected: make_list("ge 0.5.3-r2"), vulnerable: make_list("lt 0.5.3-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/multi-aterm", unaffected: make_list("ge 0.2.1-r1"), vulnerable: make_list("lt 0.2.1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/rxvt", unaffected: make_list("ge 2.7.10-r4"), vulnerable: make_list("lt 2.7.10-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/rxvt-unicode", unaffected: make_list("ge 9.02-r1"), vulnerable: make_list("lt 9.02-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/wterm", unaffected: make_list("ge 6.2.9-r3"), vulnerable: make_list("lt 6.2.9-r3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
