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
tag_insight = "Multiple vulnerabilities in the Horde Application Framework can allow for
    arbitrary files to be overwritten and cross-site scripting attacks.";
tag_solution = "All Horde users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-3.3.5

All Horde webmail users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-webmail-1.2.4

All Horde groupware users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-groupware-1.2.4

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200911-01
http://bugs.gentoo.org/show_bug.cgi?id=285052";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200911-01.";

                                                                                
                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66148);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
 script_cve_id("CVE-2009-3236", "CVE-2009-3237");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Gentoo Security Advisory GLSA 200911-01 (horde horde-webmail horde-groupware)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200911-01 (horde horde-webmail horde-groupware)");

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
if ((res = ispkgvuln(pkg:"www-apps/horde", unaffected: make_list("ge 3.3.5"), vulnerable: make_list("lt 3.3.5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-webmail", unaffected: make_list("ge 1.2.4"), vulnerable: make_list("lt 1.2.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-groupware", unaffected: make_list("ge 1.2.4"), vulnerable: make_list("lt 1.2.4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
