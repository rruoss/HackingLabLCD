#
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Multiple vulnerabilities have been found in FreeType, allowing
    remote attackers to possibly execute arbitrary code or cause a Denial
of
    Service.";
tag_solution = "All FreeType users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-libs/freetype-2.4.8'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201201-09
http://bugs.gentoo.org/show_bug.cgi?id=332701
http://bugs.gentoo.org/show_bug.cgi?id=342121
http://bugs.gentoo.org/show_bug.cgi?id=345843
http://bugs.gentoo.org/show_bug.cgi?id=377143
http://bugs.gentoo.org/show_bug.cgi?id=387535
http://bugs.gentoo.org/show_bug.cgi?id=390623";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201201-09.";

                                                                                
                                                                                
if(description)
{
 script_id(70810);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-1797", "CVE-2010-2497", "CVE-2010-2498", "CVE-2010-2499", "CVE-2010-2500", "CVE-2010-2519", "CVE-2010-2520", "CVE-2010-2527", "CVE-2010-2541", "CVE-2010-2805", "CVE-2010-2806", "CVE-2010-2807", "CVE-2010-2808", "CVE-2010-3053", "CVE-2010-3054", "CVE-2010-3311", "CVE-2010-3814", "CVE-2010-3855", "CVE-2011-0226", "CVE-2011-3256", "CVE-2011-3439");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-12 10:04:42 -0500 (Sun, 12 Feb 2012)");
 script_name("Gentoo Security Advisory GLSA 201201-09 (FreeType)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 201201-09 (FreeType)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
if((res = ispkgvuln(pkg:"media-libs/freetype", unaffected: make_list("ge 2.4.8"), vulnerable: make_list("lt 2.4.8"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
