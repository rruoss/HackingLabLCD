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
tag_insight = "New releases of Mozilla, Epiphany, Mozilla Thunderbird, and Mozilla Firefox
fix several vulnerabilities, including the remote execution of arbitrary
code.";
tag_solution = "All users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv your-version
    # emerge your-version

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200409-26
http://bugs.gentoo.org/show_bug.cgi?id=63996
http://www.mozilla.org/projects/security/known-vulnerabilities.html#mozilla1.7.3
http://www.us-cert.gov/cas/techalerts/TA04-261A.html";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200409-26.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(54682);
 script_cve_id("CVE-2004-0902","CVE-2004-0903","CVE-2004-0904","CVE-2004-0905","CVE-2004-0906","CVE-2004-0907","CVE-2004-0908","CVE-2004-0909");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Gentoo Security Advisory GLSA 200409-26 (Mozilla)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200409-26 (Mozilla)");

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
if ((res = ispkgvuln(pkg:"net-www/mozilla", unaffected: make_list("ge 1.7.3"), vulnerable: make_list("lt 1.7.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-firefox", unaffected: make_list("ge 1.0_pre"), vulnerable: make_list("lt 1.0_pre"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird", unaffected: make_list("ge 0.8"), vulnerable: make_list("lt 0.8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-bin", unaffected: make_list("ge 1.7.3"), vulnerable: make_list("lt 1.7.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-firefox-bin", unaffected: make_list("ge 1.0_pre"), vulnerable: make_list("lt 1.0_pre"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 0.8"), vulnerable: make_list("lt 0.8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/epiphany", unaffected: make_list("ge 1.2.9-r1"), vulnerable: make_list("lt 1.2.9-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
