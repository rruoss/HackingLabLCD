#
#ADV FreeBSD-SA-04:14.cvs.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
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
#

include("revisions-lib.inc");
tag_insight = "The Concurrent Versions System (CVS) is a version control system.  It
may be used to access a repository locally, or to access a `remote
repository' using a number of different methods.  When accessing a
remote repository, the target machine runs the CVS server to fulfill
client requests.

A number of vulnerabilities were discovered in CVS by Stefan Esser,
Sebastian Krahmer, and Derek Price.

 . Insufficient input validation while processing Entry lines.
   (CVE-2004-0414)

 . A double-free resulting from erroneous state handling while
   processing Argumentx commands. (CVE-2004-0416)

 . Integer overflow while processing Max-dotdot commands.
   (CVE-2004-0417)

 . Erroneous handling of empty entries handled while processing
   Notify commands. (CVE-2004-0418)

 . A format string bug while processing CVS wrappers.

 . Single-byte buffer underflows while processing configuration files
   from CVSROOT.

 . Various other integer overflows.

Additionally, iDEFENSE reports an undocumented command-line flag used
in debugging does not perform input validation on the given path
names.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-04:14.cvs.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-04:14.cvs.asc";

                                                                                
if(description)
{
 script_id(52656);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-0414", "CVE-2004-0778");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "FreeBSD Security Advisory (FreeBSD-SA-04:14.cvs.asc)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "FreeBSD Security Advisory (FreeBSD-SA-04:14.cvs.asc)";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 family = "FreeBSD Local Security Checks";
 script_family(family);
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
if(patchlevelcmp(rel:"4.10", patchlevel:"3")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.9", patchlevel:"12")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"25")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.2.1", patchlevel:"10")<0) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
