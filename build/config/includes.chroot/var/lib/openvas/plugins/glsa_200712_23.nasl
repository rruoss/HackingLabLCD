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
tag_insight = "Multiple vulnerabilities have been discovered in Wireshark, allowing for
the remote execution of arbitrary code and a Denial of Service.";
tag_solution = "All Wireshark users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/wireshark-0.99.7'

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200712-23
http://bugs.gentoo.org/show_bug.cgi?id=199958";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200712-23.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(60085);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2007-6111", "CVE-2007-6112", "CVE-2007-6113", "CVE-2007-6114", "CVE-2007-6115", "CVE-2007-6116", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6119", "CVE-2007-6120", "CVE-2007-6121", "CVE-2007-6438", "CVE-2007-6439", "CVE-2007-6441", "CVE-2007-6450", "CVE-2007-6451");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Gentoo Security Advisory GLSA 200712-23 (wireshark)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200712-23 (wireshark)");

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
if ((res = ispkgvuln(pkg:"net-analyzer/wireshark", unaffected: make_list("ge 0.99.7"), vulnerable: make_list("lt 0.99.7"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
