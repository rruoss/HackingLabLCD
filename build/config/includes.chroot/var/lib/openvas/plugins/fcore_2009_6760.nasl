# OpenVAS Vulnerability Test
# $Id: fcore_2009_6760.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-6760 (deluge)
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

Deluge 1.1.9 contains updated translations and fixes for a move torrent issue
(now only happens when the torrent has data downloaded), a folder renaming bug
(renaming a parent folder into multiple folders), and an issue with adding a
remote torrent in the WebUI.    This update also includes all upstream bug-fixes
and enhancements in versions 1.1.7 and 1.1.8 (which were skipped in this
package). For a full list of these changes, please see the upstream changelog:
http://dev.deluge-torrent.org/wiki/ChangeLog    In addition, the included copy
of rb_libtorrent has been updated to fix a potential directory traversal
vulnerability which would allow a remote attacker to create or overwrite
arbitrary files via a .. (dot dot) and partial relative pathname in a
specially-crafted torrent.

ChangeLog:

* Wed Jun 17 2009 Peter Gordon  - 1.1.9-1
- Update to new upstream bug-fix release (1.1.9), updates internal libtorrent
copy to fix CVE-2009-1760 (#505523).
- Adds dependency on chardet for fixing lots of bugs with torrents
which are not encoded as UTF-8.
- Add back the flags, in an optional -flags subpackage as per the new Flags
policy (Package_Maintainers_Flags_Policy on the wiki).
- Add LICENSE and README to installed documentation.";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update deluge' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6760";
tag_summary = "The remote host is missing an update to deluge
announced via advisory FEDORA-2009-6760.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64304);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
 script_cve_id("CVE-2009-1760");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Fedora Core 10 FEDORA-2009-6760 (deluge)");


 script_description(desc);

 script_summary("Fedora Core 10 FEDORA-2009-6760 (deluge)");

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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=505523");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"deluge", rpm:"deluge~1.1.9~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"deluge-flags", rpm:"deluge-flags~1.1.9~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"deluge-debuginfo", rpm:"deluge-debuginfo~1.1.9~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
