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
tag_insight = "KDM allows logins without password under certain circumstances allowing a
local user to gain elevated privileges.";
tag_solution = "All KDM users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdm-3.5.7-r2'

All kdebase users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdebase-3.5.7-r4'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200710-15
http://bugs.gentoo.org/show_bug.cgi?id=192373";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200710-15.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(58676);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2007-4569");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Gentoo Security Advisory GLSA 200710-15 (KDM)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200710-15 (KDM)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = ispkgvuln(pkg:"kde-base/kdm", unaffected: make_list("ge 3.5.7-r2"), vulnerable: make_list("lt 3.5.7-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kdebase", unaffected: make_list("ge 3.5.7-r4"), vulnerable: make_list("lt 3.5.7-r4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}