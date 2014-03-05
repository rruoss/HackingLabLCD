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
tag_insight = "Multiple vulnerabilities were found in Apache Tomcat, the worst of
which allowing to read, modify and overwrite arbitrary files.";
tag_solution = "All Apache Tomcat 6.0.x users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/tomcat-6.0.35'
    

All Apache Tomcat 7.0.x users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/tomcat-7.0.23'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-24
http://bugs.gentoo.org/show_bug.cgi?id=272566
http://bugs.gentoo.org/show_bug.cgi?id=273662
http://bugs.gentoo.org/show_bug.cgi?id=303719
http://bugs.gentoo.org/show_bug.cgi?id=320963
http://bugs.gentoo.org/show_bug.cgi?id=329937
http://bugs.gentoo.org/show_bug.cgi?id=373987
http://bugs.gentoo.org/show_bug.cgi?id=374619
http://bugs.gentoo.org/show_bug.cgi?id=382043
http://bugs.gentoo.org/show_bug.cgi?id=386213
http://bugs.gentoo.org/show_bug.cgi?id=396401
http://bugs.gentoo.org/show_bug.cgi?id=399227";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201206-24.";

                                                                                
                                                                                
if(description)
{
 script_id(71550);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783", "CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902", "CVE-2010-1157", "CVE-2010-2227", "CVE-2010-3718", "CVE-2010-4172", "CVE-2010-4312", "CVE-2011-0013", "CVE-2011-0534", "CVE-2011-1088", "CVE-2011-1183", "CVE-2011-1184", "CVE-2011-1419", "CVE-2011-1475", "CVE-2011-1582", "CVE-2011-2204", "CVE-2011-2481", "CVE-2011-2526", "CVE-2011-2729", "CVE-2011-3190", "CVE-2011-3375", "CVE-2011-4858", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064", "CVE-2012-0022");
 script_tag(name:"risk_factor", value:"High");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:53 -0400 (Fri, 10 Aug 2012)");
 script_name("Gentoo Security Advisory GLSA 201206-24 (apache tomcat)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 201206-24 (apache tomcat)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/packages");
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
if((res = ispkgvuln(pkg:"www-servers/tomcat", unaffected: make_list("rge 6.0.35", "ge 7.0.23"), vulnerable: make_list("rlt 5.5.34", "rlt 6.0.35", "lt 7.0.23"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
