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
tag_insight = "Multiple packages suffer from RUNPATH issues that may allow users in the
'portage' group to escalate privileges.";
tag_solution = "All Perl users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/perl

All Qt-UnixODBC users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-db/qt-unixodbc-3.3.4-r1'

All CMake users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose dev-util/cmake

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200510-14
http://bugs.gentoo.org/show_bug.cgi?id=105719
http://bugs.gentoo.org/show_bug.cgi?id=105721
http://bugs.gentoo.org/show_bug.cgi?id=106678";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200510-14.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(55649);
 script_cve_id("CVE-2005-4278","CVE-2005-4279","CVE-2005-4280");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_tag(name:"risk_factor", value:"High");
 script_name("Gentoo Security Advisory GLSA 200510-14 (Perl Qt-UnixODBC CMake)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200510-14 (Perl Qt-UnixODBC CMake)");

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
if ((res = ispkgvuln(pkg:"dev-lang/perl", unaffected: make_list("ge 5.8.7-r1", "rge 5.8.6-r6"), vulnerable: make_list("lt 5.8.7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-db/qt-unixodbc", unaffected: make_list("ge 3.3.4-r1"), vulnerable: make_list("lt 3.3.4-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-util/cmake", unaffected: make_list("ge 2.2.0-r1", "rge 2.0.6-r1"), vulnerable: make_list("lt 2.2.0-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
