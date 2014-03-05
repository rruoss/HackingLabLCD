#
#ADV FreeBSD-SA-08:03.sendfile.asc
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
tag_insight = "The sendfile(2) system call allows a server application (such as a
HTTP or FTP server) to transmit the contents of a file over a network
connection without first copying it to application memory.  High
performance servers such as the Apache HTTP Server and ftpd use sendfile.

When a process opens a file (and other file system objects, such as
directories), it specifies access flags indicating its intent to read,
write, or perform other operations.  These flags are checked against
file system permissions, and then stored in the resulting file
descriptor to validate future operations against.

The sendfile(2) system call does not check the file descriptor access
flags before sending data from a file.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-08:03.sendfile.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-08:03.sendfile.asc";

                                                                                
if(description)
{
 script_id(60399);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-0777");
 script_tag(name:"cvss_base", value:"4.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "FreeBSD Security Advisory (FreeBSD-SA-08:03.sendfile.asc)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "FreeBSD Security Advisory (FreeBSD-SA-08:03.sendfile.asc)";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if(patchlevelcmp(rel:"6.3", patchlevel:"1")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.2", patchlevel:"11")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.1", patchlevel:"23")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.5", patchlevel:"19")<0) {
    vuln = 1;
}

if(vuln) {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
