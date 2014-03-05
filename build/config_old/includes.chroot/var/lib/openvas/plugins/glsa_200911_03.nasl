#
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
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
tag_insight = "Multiple vulnerabilities have been found in the UW IMAP toolkit and the
    c-client library, the worst of which leading to the execution of
arbitrary
    code.";
tag_solution = "All c-client library users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/c-client-2007e'

All UW IMAP toolkit users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/uw-imap-2007e'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200911-03
http://bugs.gentoo.org/show_bug.cgi?id=245425
http://bugs.gentoo.org/show_bug.cgi?id=252567";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200911-03.";

                                                                                
                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66333);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-03 22:10:42 +0100 (Thu, 03 Dec 2009)");
 script_cve_id("CVE-2008-5005", "CVE-2008-5006", "CVE-2008-5514");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Gentoo Security Advisory GLSA 200911-03 (c-client uw-imap)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200911-03 (c-client uw-imap)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = ispkgvuln(pkg:"net-libs/c-client", unaffected: make_list("ge 2007e"), vulnerable: make_list("lt 2007e"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-mail/uw-imap", unaffected: make_list("ge 2007e"), vulnerable: make_list("lt 2007e"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
