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
tag_insight = "Multiple vulnerabilities have been identified in Sun Java Development Kit
(JDK) and Java Runtime Environment (JRE).";
tag_solution = "All Sun JRE users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose 'dev-java/sun-jre-bin'

All Sun JDK users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose 'dev-java/sun-jdk'

All emul-linux-x86-java users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose 'app-emulation/emul-linux-x86-java'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200804-20
http://bugs.gentoo.org/show_bug.cgi?id=178851
http://bugs.gentoo.org/show_bug.cgi?id=178962
http://bugs.gentoo.org/show_bug.cgi?id=183580
http://bugs.gentoo.org/show_bug.cgi?id=185256
http://bugs.gentoo.org/show_bug.cgi?id=194711
http://bugs.gentoo.org/show_bug.cgi?id=212425
http://www.gentoo.org/security/en/glsa/glsa-200705-23.xml
http://www.gentoo.org/security/en/glsa/glsa-200706-08.xml";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200804-20.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(60820);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2007-2435", "CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3655", "CVE-2007-5232", "CVE-2007-5237", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274", "CVE-2007-5689", "CVE-2008-0628", "CVE-2008-0657", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Gentoo Security Advisory GLSA 200804-20 (sun-jdk, sun-jre-bin, emul-linux-x86-java)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200804-20 (sun-jdk, sun-jre-bin, emul-linux-x86-java)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = ispkgvuln(pkg:"dev-java/sun-jre-bin", unaffected: make_list("ge 1.6.0.05", "rge 1.5.0.15", "rge 1.4.2.17"), vulnerable: make_list("lt 1.6.0.05"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-java/sun-jdk", unaffected: make_list("ge 1.6.0.05", "rge 1.5.0.15", "rge 1.4.2.17"), vulnerable: make_list("lt 1.6.0.05"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-emulation/emul-linux-x86-java", unaffected: make_list("ge 1.6.0.05", "rge 1.5.0.15", "rge 1.4.2.17"), vulnerable: make_list("lt 1.6.0.05"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
