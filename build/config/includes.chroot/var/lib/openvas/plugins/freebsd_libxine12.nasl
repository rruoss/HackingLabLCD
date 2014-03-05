#
#VID 51d1d428-42f0-11de-ad22-000e35248ad7
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 51d1d428-42f0-11de-ad22-000e35248ad7
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "The following package is affected: libxine

CVE-2009-0698
Integer overflow in the 4xm demuxer (demuxers/demux_4xm.c) in xine-lib
1.1.16.1 allows remote attackers to cause a denial of service (crash)
and possibly execute arbitrary code via a 4X movie file with a large
current_track value, a similar issue to CVE-2009-0385.

CVE-2008-5234
Multiple heap-based buffer overflows in xine-lib 1.1.12, and other
versions before 1.1.15, allow remote attackers to execute arbitrary
code via vectors related to (1) a crafted metadata atom size processed
by the parse_moov_atom function in demux_qt.c and (2) frame reading in
the id3v23_interp_frame function in id3.c.  NOTE: as of 20081122, it is
possible that vector 1 has not been fixed in 1.1.15.

CVE-2008-5240
xine-lib 1.1.12, and other 1.1.15 and earlier versions, relies on an
untrusted input value to determine the memory allocation and does not
check the result for (1) the MATROSKA_ID_TR_CODECPRIVATE track entry
element processed by demux_matroska.c; and (2) PROP_TAG, (3) MDPR_TAG,
and (4) CONT_TAG chunks processed by the real_parse_headers function
in demux_real.c; which allows remote attackers to cause a denial of
service (NULL pointer dereference and crash) or possibly execute
arbitrary code via a crafted value.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://trapkit.de/advisories/TKADV2009-004.txt
http://sourceforge.net/project/shownotes.php?release_id=660071
http://www.vuxml.org/freebsd/51d1d428-42f0-11de-ad22-000e35248ad7.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64000);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-20 00:17:15 +0200 (Wed, 20 May 2009)");
 script_cve_id("CVE-2009-0698", "CVE-2008-5234", "CVE-2008-5240");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: libxine");


 script_description(desc);

 script_summary("FreeBSD Ports: libxine");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
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

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"libxine");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.16.2")<0) {
    txt += 'Package libxine version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
