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
tag_insight = "Multiple vulnerabilities have been discovered in Horde and two modules,
    allowing for the execution of arbitrary code, information disclosure,
or
    Cross-Site Scripting.";
tag_solution = "All Horde users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-3.3.4

All Horde IMP users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-imp-4.3.4

All Horde Passwd users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-passwd-3.1.1

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200909-14
http://bugs.gentoo.org/show_bug.cgi?id=256125
http://bugs.gentoo.org/show_bug.cgi?id=262976
http://bugs.gentoo.org/show_bug.cgi?id=262978
http://bugs.gentoo.org/show_bug.cgi?id=277294";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200909-14.";

                                                                                
                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64883);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
 script_cve_id("CVE-2008-5917", "CVE-2009-0930", "CVE-2009-0931", "CVE-2009-0932", "CVE-2009-2360");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_name("Gentoo Security Advisory GLSA 200909-14 (horde horde-imp horde-passwd)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200909-14 (horde horde-imp horde-passwd)");

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
if ((res = ispkgvuln(pkg:"www-apps/horde", unaffected: make_list("ge 3.3.4"), vulnerable: make_list("lt 3.3.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-imp", unaffected: make_list("ge 4.3.4"), vulnerable: make_list("lt 4.3.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-passwd", unaffected: make_list("ge 3.1.1"), vulnerable: make_list("lt 3.1.1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
