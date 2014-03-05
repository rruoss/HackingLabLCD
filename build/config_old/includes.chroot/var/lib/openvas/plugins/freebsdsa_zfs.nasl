#
#ADV FreeBSD-SA-10:03.zfs.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-10:03.zfs.asc
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "ZFS is a file-system originally developed by Sun Microsystems.

The ZFS Intent Log (ZIL) is a mechanism that gathers together in memory
transactions of writes, and is flushed onto disk when synchronous
semantics is necessary.  In the event of crash or power failure, the
log is examined and the uncommitted transaction would be replayed to
maintain the synchronous semantics.

When replaying setattr transaction, the replay code would set the
attributes with certain insecure defaults, when the logged
transaction did not touch these attributes.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-10:03.zfs.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-10:03.zfs.asc";


if(description)
{
 script_id(66663);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-11 23:48:26 +0100 (Mon, 11 Jan 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("FreeBSD Security Advisory (FreeBSD-SA-10:03.zfs.asc)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 script_summary("FreeBSD Security Advisory (FreeBSD-SA-10:03.zfs.asc)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdpatchlevel", "login/SSH/success");
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
vuln = 0;
if(patchlevelcmp(rel:"8.0", patchlevel:"2")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.2", patchlevel:"6")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.1", patchlevel:"10")<0) {
    vuln = 1;
}

if(vuln) {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
