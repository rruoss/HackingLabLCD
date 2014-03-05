# OpenVAS Vulnerability Test
# $Id: fcore_2009_8565.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-8565 (gnutls)
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
tag_insight = "Update Information:

This update fixes handling of NUL characters in certificate  Common Name or
subjectAltName fields especially in regards to comparsion to hostnames.

ChangeLog:

* Wed Sep 23 2009 Tomas Mraz  2.6.6-3
- fix handling of hostname in openpgp certificates
* Fri Aug 14 2009 Tomas Mraz  2.6.6-2
- fix CVE-2009-2730 - handling of NUL chars in certificate CNs and SANs";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update gnutls' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8565";
tag_summary = "The remote host is missing an update to gnutls
announced via advisory FEDORA-2009-8565.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64969);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
 script_cve_id("CVE-2009-2730");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Fedora Core 11 FEDORA-2009-8565 (gnutls)");


 script_description(desc);

 script_summary("Fedora Core 11 FEDORA-2009-8565 (gnutls)");

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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=516231");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.6.6~3.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~2.6.6~3.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnutls-guile", rpm:"gnutls-guile~2.6.6~3.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnutls-utils", rpm:"gnutls-utils~2.6.6~3.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnutls-debuginfo", rpm:"gnutls-debuginfo~2.6.6~3.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
