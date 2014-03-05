# OpenVAS Vulnerability Test
# $Id: fcore_2009_2285.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-2285 (psi)
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
tag_insight = "This is a bugfix-only update to version 0.12.1    New in 0.12.1   - Bugfix for
DOS vulnerability in the file transfer code.     Thanks to Jesus Olmos
(jolmos@isecauditors.com)

ChangeLog:

* Tue Mar  3 2009 Sven Lankes  0.12.1-1
- version 0.12.1";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update psi' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2285";
tag_summary = "The remote host is missing an update to psi
announced via advisory FEDORA-2009-2285.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63488);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
 script_cve_id("CVE-2008-6393");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Fedora Core 10 FEDORA-2009-2285 (psi)");


 script_description(desc);

 script_summary("Fedora Core 10 FEDORA-2009-2285 (psi)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Fedora Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=488299");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"psi", rpm:"psi~0.12.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"psi-i18n", rpm:"psi-i18n~0.12.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"psi-icons", rpm:"psi-icons~0.12.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"psi-debuginfo", rpm:"psi-debuginfo~0.12.1~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}