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
tag_insight = "In certain configurations, it can be possible to bypass restrictions set by
the 'SSLCipherSuite' directive of mod_ssl.";
tag_solution = "All Apache 2 users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=net-www/apache-2.0.52'
    # emerge '>=net-www/apache-2.0.52'

All mod_ssl users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=net-www/mod_ssl-2.8.20'
    # emerge '>=net-www/mod_ssl-2.8.20'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200410-21
http://bugs.gentoo.org/show_bug.cgi?id=66807
http://issues.apache.org/bugzilla/show_bug.cgi?id=31505";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200410-21.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(54712);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_bugtraq_id(11360);
 script_cve_id("CVE-2004-0885");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Gentoo Security Advisory GLSA 200410-21 (apache)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200410-21 (apache)");

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
if ((res = ispkgvuln(pkg:"net-www/apache", unaffected: make_list("ge 2.0.52", "lt 2.0"), vulnerable: make_list("lt 2.0.52"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mod_ssl", unaffected: make_list("ge 2.8.20"), vulnerable: make_list("lt 2.8.20"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}