# OpenVAS Vulnerability Test
# $Id: mdksa_2009_139.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:139 (libtorrent-rasterbar)
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
tag_insight = "A security vulnerability has been identified and corrected in
libtorrent-rasterbar:

Directory traversal vulnerability in src/torrent_info.cpp in Rasterbar
libtorrent before 0.14.4, as used in firetorrent, qBittorrent, deluge
Torrent, and other applications, allows remote attackers to create
or overwrite arbitrary files via a .. (dot dot) and partial relative
pathname in a Multiple File Mode list element in a .torrent file
(CVE-2009-1760).

The updated packages have been patched to prevent this.

Affected: 2009.1";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:139";
tag_summary = "The remote host is missing an update to libtorrent-rasterbar
announced via advisory MDVSA-2009:139.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64285);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
 script_cve_id("CVE-2009-1760");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Mandrake Security Advisory MDVSA-2009:139 (libtorrent-rasterbar)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:139 (libtorrent-rasterbar)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"libtorrent-rasterbar1", rpm:"libtorrent-rasterbar1~0.14.1~4.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtorrent-rasterbar-devel", rpm:"libtorrent-rasterbar-devel~0.14.1~4.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-libtorrent-rasterbar", rpm:"python-libtorrent-rasterbar~0.14.1~4.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64torrent-rasterbar1", rpm:"lib64torrent-rasterbar1~0.14.1~4.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64torrent-rasterbar-devel", rpm:"lib64torrent-rasterbar-devel~0.14.1~4.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
