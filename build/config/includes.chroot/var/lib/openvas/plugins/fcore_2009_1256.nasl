# OpenVAS Vulnerability Test
# $Id: fcore_2009_1256.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-1256 (roundcubemail)
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

Upgrade to 0.2 stable.

Following security fix is included as well:
Common Vulnerabilities and Exposures assigned an identifier
CVE-2009-0413 to  the following vulnerability:

Cross-site scripting (XSS) vulnerability in RoundCube Webmail
(roundcubemail) 0.2 stable allows remote attackers to inject
arbitrary web script or HTML via the background attribute
embedded in an HTML e-mail message.

ChangeLog:

* Wed Feb  4 2009 Jon Ciesla  = 0.2-7.stable
- Patch for CVE-2009-0413, BZ 484052.
* Mon Jan  5 2009 Jon Ciesla  = 0.2-6.stable
- New upstream.
- Dropped two most recent patches, applied upstream.";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update roundcubemail' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1256";
tag_summary = "The remote host is missing an update to roundcubemail
announced via advisory FEDORA-2009-1256.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63327);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-02-10 15:52:40 +0100 (Tue, 10 Feb 2009)");
 script_cve_id("CVE-2009-0413");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Fedora Core 9 FEDORA-2009-1256 (roundcubemail)");


 script_description(desc);

 script_summary("Fedora Core 9 FEDORA-2009-1256 (roundcubemail)");

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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=484052");
 script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0413");
 script_xref(name : "URL" , value : "http://trac.roundcube.net/changeset/2245");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/33372");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/33622");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48129");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~0.2~7.stable.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
