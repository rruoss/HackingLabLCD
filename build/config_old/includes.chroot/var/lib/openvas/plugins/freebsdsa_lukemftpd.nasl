#
#ADV FreeBSD-SA-09:01.lukemftpd.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-09:01.lukemftpd.asc
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
tag_insight = "lukemftpd(8) is a general-purpose implementation of File Transfer Protocol
(FTP) server that is shipped with the FreeBSD base system.  It is not enabled
in default installations but can be enabled as either an inetd(8) server,
or a standard-alone server.

A cross-site request forgery attack is a type of malicious exploit that is
mainly targeted to a web browser, by tricking a user trusted by the site
into visiting a specially crafted URL, which in turn executes a command
which performs some privileged operations on behalf of the trusted user
on the victim site.

The lukemftpd(8) server splits long commands into several requests.  This
may result in the server executing a command which is hidden inside
another very long command.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-09:01.lukemftpd.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-09:01.lukemftpd.asc";


if(description)
{
 script_id(63175);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
 script_cve_id("CVE-2008-4247");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "FreeBSD Security Advisory (FreeBSD-SA-09:01.lukemftpd.asc)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "FreeBSD Security Advisory (FreeBSD-SA-09:01.lukemftpd.asc)";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if(patchlevelcmp(rel:"7.1", patchlevel:"1")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.0", patchlevel:"8")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.4", patchlevel:"2")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.3", patchlevel:"8")<0) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
