# OpenVAS Vulnerability Test
# $Id: fcore_2009_11499.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-11499 (libsndfile)
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

Version 1.0.20 (2009-03-14)
* Fix potential heap overflow in VOC file parser
  (Tobias Klein, http://www.trapkit.de/).
Version 1.0.19 (2009-03-02)
* Fix for CVE-2009-0186 (Alin Rad Pop, Secunia Research).
* Huge number of minor bug fixes as a result of static analysis.
Version 1.0.18 (2009-02-07)
* Add Ogg/Vorbis support (thanks to John ffitch).
* Remove captive FLAC library.
* Many new features and bug fixes.

ChangeLog:

* Sat Nov 14 2009 Orcan Ogetbil  - 1.0.20-3
- Add FLAC/Ogg/Vorbis support (BR: libvorbis-devel)
- Make build verbose
- Remove rpath
- Fix ChangeLog encoding
- Move the big Changelog to the devel package";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update libsndfile' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-11499";
tag_summary = "The remote host is missing an update to libsndfile
announced via advisory FEDORA-2009-11499.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(66438);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_cve_id("CVE-2009-0186", "CVE-2009-1788", "CVE-2009-1791");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Fedora Core 10 FEDORA-2009-11499 (libsndfile)");


 script_description(desc);

 script_summary("Fedora Core 10 FEDORA-2009-11499 (libsndfile)");

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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=488361");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=502657");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=502658");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libsndfile", rpm:"libsndfile~1.0.20~3.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsndfile-devel", rpm:"libsndfile-devel~1.0.20~3.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsndfile-debuginfo", rpm:"libsndfile-debuginfo~1.0.20~3.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
