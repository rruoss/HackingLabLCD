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
tag_insight = "Kaffeine and gxine both contain a buffer overflow that can be exploited
when accessing content from a malicious HTTP server with specially crafted
headers.";
tag_solution = "All Kaffeine users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/kaffeine-0.4.3b-r1'

All gxine users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/gxine-0.3.3-r1'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200411-14
http://bugs.gentoo.org/show_bug.cgi?id=69663
http://bugs.gentoo.org/show_bug.cgi?id=70055
http://securitytracker.com/alerts/2004/Oct/1011936.html
http://sourceforge.net/tracker/index.php?func=detail&aid=1060299&group_id=9655&atid=109655";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200411-14.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(54735);
 script_cve_id("CVE-2004-1034");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Gentoo Security Advisory GLSA 200411-14 (kaffeine gxine)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200411-14 (kaffeine gxine)");

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
if ((res = ispkgvuln(pkg:"media-video/kaffeine", unaffected: make_list("ge 0.5_rc1-r1", "rge 0.4.3b-r1"), vulnerable: make_list("lt 0.5_rc1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-video/gxine", unaffected: make_list("ge 0.3.3-r1"), vulnerable: make_list("lt 0.3.3-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
