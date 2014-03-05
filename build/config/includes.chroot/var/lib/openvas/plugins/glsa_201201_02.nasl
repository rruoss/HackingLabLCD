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
tag_insight = "Multiple vulnerabilities were found in MySQL, some of which may
    allow execution of arbitrary code.";
tag_solution = "All MySQL users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mysql-5.1.56'
    

NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since May 14, 2011. It is likely that your system is
already no
      longer affected by this issue.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201201-02
http://bugs.gentoo.org/show_bug.cgi?id=220813
http://bugs.gentoo.org/show_bug.cgi?id=229329
http://bugs.gentoo.org/show_bug.cgi?id=237166
http://bugs.gentoo.org/show_bug.cgi?id=238117
http://bugs.gentoo.org/show_bug.cgi?id=240407
http://bugs.gentoo.org/show_bug.cgi?id=277717
http://bugs.gentoo.org/show_bug.cgi?id=294187
http://bugs.gentoo.org/show_bug.cgi?id=303747
http://bugs.gentoo.org/show_bug.cgi?id=319489
http://bugs.gentoo.org/show_bug.cgi?id=321791
http://bugs.gentoo.org/show_bug.cgi?id=339717
http://bugs.gentoo.org/show_bug.cgi?id=344987
http://bugs.gentoo.org/show_bug.cgi?id=351413";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 201201-02.";

                                                                                
                                                                                
if(description)
{
 script_id(70803);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_cve_id("CVE-2008-3963", "CVE-2008-4097", "CVE-2008-4098", "CVE-2008-4456", "CVE-2008-7247", "CVE-2009-2446", "CVE-2009-4019", "CVE-2009-4028", "CVE-2009-4484", "CVE-2010-1621", "CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850", "CVE-2010-2008", "CVE-2010-3676", "CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3679", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3683", "CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-12 10:04:41 -0500 (Sun, 12 Feb 2012)");
 script_name("Gentoo Security Advisory GLSA 201201-02 (MySQL)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 201201-02 (MySQL)");

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
if((res = ispkgvuln(pkg:"dev-db/mysql", unaffected: make_list("ge 5.1.56"), vulnerable: make_list("lt 5.1.56"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
