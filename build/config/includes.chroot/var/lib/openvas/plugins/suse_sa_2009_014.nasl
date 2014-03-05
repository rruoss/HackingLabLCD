# OpenVAS Vulnerability Test
# $Id: suse_sa_2009_014.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory SUSE-SA:2009:014 (acroread)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
tag_insight = "Multiple flaws in the JBIG2 decoder and the JavaScript engine of the
Adobe Reader allowed attackers to crash acroread or even execute
arbitrary code by tricking users into opening specially crafted PDF
files.

Please find more details at Adobe's site:
http://www.adobe.com/support/security/bulletins/apsb09-04.html

Note that Adobe did not provide updates for Adobe Reader 7 as used
on NLD9. We cannot upgrade to newer versions due to library
dependencies. We strongly encourage users of acroread on NLD9 to
uninstall the package and to use an alternative, open source pdf
viewer instead. We're currently evaluating the possibility of
disabling acroread on NLD9 via online update.";
tag_solution = "Update your system with the packages as indicated in
the referenced security advisory.

https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:014";
tag_summary = "The remote host is missing updates announced in
advisory SUSE-SA:2009:014.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63686);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
 script_cve_id("CVE-2009-0193", "CVE-2009-0658", "CVE-2009-0927", "CVE-2009-0928", "CVE-2009-1061", "CVE-2009-1062");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("SuSE Security Advisory SUSE-SA:2009:014 (acroread)");


 script_description(desc);

 script_summary("SuSE Security Advisory SUSE-SA:2009:014 (acroread)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/rpms");
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

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.4~0.1.1", rls:"openSUSE11.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.4~0.1", rls:"openSUSE11.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.4~0.1", rls:"openSUSE10.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
