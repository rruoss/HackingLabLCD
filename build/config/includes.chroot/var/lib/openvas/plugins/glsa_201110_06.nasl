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
tag_insight = "Multiple vulnerabilities were found in PHP, the worst of which
    leading to remote execution of arbitrary code.";
tag_solution = "All PHP users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.3.8'
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-06
http://bugs.gentoo.org/show_bug.cgi?id=306939
http://bugs.gentoo.org/show_bug.cgi?id=332039
http://bugs.gentoo.org/show_bug.cgi?id=340807
http://bugs.gentoo.org/show_bug.cgi?id=350908
http://bugs.gentoo.org/show_bug.cgi?id=355399
http://bugs.gentoo.org/show_bug.cgi?id=358791
http://bugs.gentoo.org/show_bug.cgi?id=358975
http://bugs.gentoo.org/show_bug.cgi?id=369071
http://bugs.gentoo.org/show_bug.cgi?id=372745
http://bugs.gentoo.org/show_bug.cgi?id=373965
http://bugs.gentoo.org/show_bug.cgi?id=380261";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201110-06.";

                                                                                
                                                                                
if(description)
{
 script_id(70769);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2006-7243", "CVE-2009-5016", "CVE-2010-1128", "CVE-2010-1129", "CVE-2010-1130", "CVE-2010-1860", "CVE-2010-1861", "CVE-2010-1862", "CVE-2010-1864", "CVE-2010-1866", "CVE-2010-1868", "CVE-2010-1914", "CVE-2010-1915", "CVE-2010-1917", "CVE-2010-2093", "CVE-2010-2094", "CVE-2010-2097", "CVE-2010-2100", "CVE-2010-2101", "CVE-2010-2190", "CVE-2010-2191", "CVE-2010-2225", "CVE-2010-2484", "CVE-2010-2531", "CVE-2010-2950", "CVE-2010-3062", "CVE-2010-3063", "CVE-2010-3064", "CVE-2010-3065", "CVE-2010-3436", "CVE-2010-3709", "CVE-2010-3710", "CVE-2010-3870", "CVE-2010-4150", "CVE-2010-4409", "CVE-2010-4645", "CVE-2010-4697", "CVE-2010-4698", "CVE-2010-4699", "CVE-2010-4700", "CVE-2011-0420", "CVE-2011-0421", "CVE-2011-0708", "CVE-2011-0752", "CVE-2011-0753", "CVE-2011-0755", "CVE-2011-1092", "CVE-2011-1148", "CVE-2011-1153", "CVE-2011-1464", "CVE-2011-1466", "CVE-2011-1467", "CVE-2011-1468", "CVE-2011-1469", "CVE-2011-1470", "CVE-2011-1471", "CVE-2011-1657", "CVE-2011-1938", "CVE-2011-2202", "CVE-2011-2483", "CVE-2011-3182", "CVE-2011-3189", "CVE-2011-3267", "CVE-2011-3268");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-12 10:04:39 -0500 (Sun, 12 Feb 2012)");
 script_name("Gentoo Security Advisory GLSA 201110-06 (php)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 201110-06 (php)");

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
if((res = ispkgvuln(pkg:"dev-lang/php", unaffected: make_list("ge 5.3.8"), vulnerable: make_list("lt 5.3.8"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
