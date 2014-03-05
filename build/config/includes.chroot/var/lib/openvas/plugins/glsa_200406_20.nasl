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
tag_insight = "FreeS/WAN, Openswan, strongSwan and Super-FreeS/WAN contain two bugs when
authenticating PKCS#7 certificates. This could allow an attacker to
authenticate with a fake certificate.";
tag_solution = "All FreeS/WAN 1.9x users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '=net-misc/freeswan-1.99-r1'
    # emerge '=net-misc/freeswan-1.99-r1'

All FreeS/WAN 2.x users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '>=net-misc/freeswan-2.04-r1'
    # emerge '>=net-misc/freeswan-2.04-r1'

All Openswan 1.x users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '=net-misc/openswan-1.0.6_rc1'
    # emerge '=net-misc/openswan-1.0.6_rc1'

All Openswan 2.x users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '>=net-misc/openswan-2.1.4'
    # emerge '>=net-misc/openswan-2.1.4'

All strongSwan users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '>=net-misc/strongswan-2.1.3'
    # emerge '>=net-misc/strongswan-2.1.3'

All Super-FreeS/WAN users should migrate to the latest stable version of
Openswan. Note that Portage will force a move for Super-FreeS/WAN users to
Openswan.

    # emerge sync

    # emerge -pv '=net-misc/openswan-1.0.6_rc1'
    # emerge '=net-misc/openswan-1.0.6_rc1'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200406-20
http://lists.openswan.org/pipermail/dev/2004-June/000370.html";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200406-20.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(54605);
 script_cve_id("CVE-2004-0590");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Gentoo Security Advisory GLSA 200406-20 (Openswan)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200406-20 (Openswan)");

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
if ((res = ispkgvuln(pkg:"net-misc/freeswan", unaffected: make_list("ge 2.04-r1", "eq 1.99-r1"), vulnerable: make_list("lt 2.04-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-misc/openswan", unaffected: make_list("ge 2.1.4", "eq 1.0.6_rc1"), vulnerable: make_list("lt 2.1.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-misc/strongswan", unaffected: make_list("ge 2.1.3"), vulnerable: make_list("lt 2.1.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-misc/super-freeswan", unaffected: make_list(), vulnerable: make_list("le 1.99.7.3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
