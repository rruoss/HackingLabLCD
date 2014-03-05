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
tag_insight = "libXpm, the X Pixmap library that is a part of the X Window System,
contains multiple stack and integer overflows that may allow a
carefully-crafted XPM file to crash applications linked against libXpm,
potentially allowing the execution of arbitrary code.";
tag_solution = "All X.org users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=x11-base/xorg-x11-6.7.0-r2'
    # emerge '>=x11-base/xorg-x11-6.7.0-r2'

All XFree86 users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=x11-base/xfree-4.3.0-r7'
    # emerge '>=x11-base/xfree-4.3.0-r7'

Note: Usage of XFree86 is deprecated on the AMD64, HPPA, IA64, MIPS, PPC
and SPARC architectures: XFree86 users on those architectures should
switch to X.org rather than upgrading XFree86.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200409-34
http://bugs.gentoo.org/show_bug.cgi?id=64152
http://freedesktop.org/pipermail/xorg/2004-September/003196.html
http://freedesktop.org/pipermail/xorg/2004-September/003172.html";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200409-34.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(54690);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2004-0687", "CVE-2004-0688");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Gentoo Security Advisory GLSA 200409-34 (X)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200409-34 (X)");

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
if ((res = ispkgvuln(pkg:"x11-base/xorg-x11", unaffected: make_list("rge 6.7.0-r2", "ge 6.8.0-r1"), vulnerable: make_list("lt 6.7.0-r2", "eq 6.8.0"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-base/xfree", unaffected: make_list("ge 4.3.0-r7"), vulnerable: make_list("lt 4.3.0-r7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-base/xfree", unaffected: make_list(), vulnerable: make_list("lt 4.3.0-r7"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
