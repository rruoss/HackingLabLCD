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
tag_insight = "Two bugs in PHP may allow the disclosure of portions of memory and allow
remote attackers to upload files to arbitrary locations.";
tag_solution = "All PHP, mod_php and php-cgi users should upgrade to the latest stable
version:

    # emerge sync

    # emerge -pv '>=dev-php/php-4.3.9'
    # emerge '>=dev-php/php-4.3.9'

    # emerge -pv '>=dev-php/mod_php-4.3.9'
    # emerge '>=dev-php/mod_php-4.3.9'

    # emerge -pv '>=dev-php/php-cgi-4.3.9'
    # emerge '>=dev-php/php-cgi-4.3.9'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200410-04
http://bugs.gentoo.org/show_bug.cgi?id=64223
http://secunia.com/advisories/12560/
http://www.securityfocus.com/archive/1/375294
http://www.securityfocus.com/archive/1/375370";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200410-04.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(54695);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Gentoo Security Advisory GLSA 200410-04 (PHP)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200410-04 (PHP)");

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
if ((res = ispkgvuln(pkg:"dev-php/php", unaffected: make_list("ge 4.3.9"), vulnerable: make_list("lt 4.3.9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-php/mod_php", unaffected: make_list("ge 4.3.9"), vulnerable: make_list("lt 4.3.9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-php/php-cgi", unaffected: make_list("ge 4.3.9"), vulnerable: make_list("lt 4.3.9"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
