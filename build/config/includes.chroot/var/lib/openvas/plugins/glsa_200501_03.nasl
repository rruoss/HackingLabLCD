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
tag_insight = "Various vulnerabilities were found and fixed in Mozilla-based products,
ranging from a potential buffer overflow and temporary files disclosure to
anti-spoofing issues.";
tag_solution = "All Mozilla users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-www/mozilla-1.7.5'

All Mozilla binary users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-www/mozilla-bin-1.7.5'

All Firefox users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-www/mozilla-firefox-1.0'

All Firefox binary users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-www/mozilla-firefox-bin-1.0'

All Thunderbird users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=mail-client/mozilla-thunderbird-0.9'

All Thunderbird binary users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=mail-client/mozilla-thunderbird-bin-0.9'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200501-03
http://bugs.gentoo.org/show_bug.cgi?id=76112
http://bugs.gentoo.org/show_bug.cgi?id=68976
http://bugs.gentoo.org/show_bug.cgi?id=70749
http://isec.pl/vulnerabilities/isec-0020-mozilla.txt
http://broadcast.ptraced.net/advisories/008-firefox.thunderbird.txt
http://secunia.com/advisories/13144/";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200501-03.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(54789);
 script_cve_id("CVE-2004-2227","CVE-2004-2228");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_tag(name:"risk_factor", value:"High");
 script_name("Gentoo Security Advisory GLSA 200501-03 (Mozilla)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200501-03 (Mozilla)");

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
if ((res = ispkgvuln(pkg:"net-www/mozilla", unaffected: make_list("ge 1.7.5"), vulnerable: make_list("lt 1.7.5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-bin", unaffected: make_list("ge 1.7.5"), vulnerable: make_list("lt 1.7.5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-firefox", unaffected: make_list("ge 1.0"), vulnerable: make_list("lt 1.0"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-firefox-bin", unaffected: make_list("ge 1.0"), vulnerable: make_list("lt 1.0"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird", unaffected: make_list("ge 0.9"), vulnerable: make_list("lt 0.9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 0.9"), vulnerable: make_list("lt 0.9"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
