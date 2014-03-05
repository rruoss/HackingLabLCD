# OpenVAS Vulnerability Test
# $Id: fcore_2009_1069.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-1069 (dnsmasq)
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

Update to newer upstream version - 2.45.
Version of dnsmasq previously shipped in Fedora 9 did not
properly drop privileges, causing it to run as root
instead of intended user nobody.  Issue was caused by a
bug in kernel-headers used in build environment of the original
packages. (#454415)

New upstream version also adds DNS query source port
randomization, mitigating DNS spoofing attacks. (CVE-2008-1447)

ChangeLog:

* Mon Jul 21 2008 Patrick Jima Laughton  2.45-1
- Upstream release (bugfixes)
* Wed Jul 16 2008 Patrick Jima Laughton  2.43-2
- New upstream release, contains fixes for CVE-2008-1447/CERT VU#800113
- Dropped patch for newer glibc (merged upstream)";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update dnsmasq' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1069";
tag_summary = "The remote host is missing an update to dnsmasq
announced via advisory FEDORA-2009-1069.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63406);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-02-18 23:13:28 +0100 (Wed, 18 Feb 2009)");
 script_cve_id("CVE-2008-1447");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Fedora Core 9 FEDORA-2009-1069 (dnsmasq)");


 script_description(desc);

 script_summary("Fedora Core 9 FEDORA-2009-1069 (dnsmasq)");

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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=449345");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.45~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dnsmasq-debuginfo", rpm:"dnsmasq-debuginfo~2.45~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
