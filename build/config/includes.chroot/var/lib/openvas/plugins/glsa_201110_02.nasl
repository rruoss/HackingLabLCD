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
tag_insight = "Multiple vulnerabilities in Wireshark allow for the remote
    execution of arbitrary code, or a Denial of Service condition.";
tag_solution = "All Wireshark users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-analyzer/wireshark-1.4.9'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-02
http://bugs.gentoo.org/show_bug.cgi?id=323859
http://bugs.gentoo.org/show_bug.cgi?id=330479
http://bugs.gentoo.org/show_bug.cgi?id=339401
http://bugs.gentoo.org/show_bug.cgi?id=346191
http://bugs.gentoo.org/show_bug.cgi?id=350551
http://bugs.gentoo.org/show_bug.cgi?id=354197
http://bugs.gentoo.org/show_bug.cgi?id=357237
http://bugs.gentoo.org/show_bug.cgi?id=363895
http://bugs.gentoo.org/show_bug.cgi?id=369683
http://bugs.gentoo.org/show_bug.cgi?id=373961
http://bugs.gentoo.org/show_bug.cgi?id=381551
http://bugs.gentoo.org/show_bug.cgi?id=383823
http://bugs.gentoo.org/show_bug.cgi?id=386179";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201110-02.";

                                                                                
                                                                                
if(description)
{
 script_id(70765);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-2283", "CVE-2010-2284", "CVE-2010-2285", "CVE-2010-2286", "CVE-2010-2287", "CVE-2010-2992", "CVE-2010-2993", "CVE-2010-2994", "CVE-2010-2995", "CVE-2010-3133", "CVE-2010-3445", "CVE-2010-4300", "CVE-2010-4301", "CVE-2010-4538", "CVE-2011-0024", "CVE-2011-0444", "CVE-2011-0445", "CVE-2011-0538", "CVE-2011-0713", "CVE-2011-1138", "CVE-2011-1139", "CVE-2011-1140", "CVE-2011-1141", "CVE-2011-1142", "CVE-2011-1143", "CVE-2011-1590", "CVE-2011-1591", "CVE-2011-1592", "CVE-2011-1956", "CVE-2011-1957", "CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2174", "CVE-2011-2175", "CVE-2011-2597", "CVE-2011-2698", "CVE-2011-3266", "CVE-2011-3360", "CVE-2011-3482", "CVE-2011-3483");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-12 10:04:38 -0500 (Sun, 12 Feb 2012)");
 script_name("Gentoo Security Advisory GLSA 201110-02 (wireshark)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 201110-02 (wireshark)");

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
if((res = ispkgvuln(pkg:"net-analyzer/wireshark", unaffected: make_list("ge 1.4.9"), vulnerable: make_list("lt 1.4.9"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
