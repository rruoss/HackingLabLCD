#
#ADV FreeBSD-SA-09:10.ipv6.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-09:10.ipv6.asc
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
tag_insight = "IPv6 is a new Internet Protocol, designed to replace (and avoid many of
the problems with) the current Internet Protocol (version 4).  Many
properties of the FreeBSD IPv6 network stack can be configured via the
ioctl(2) interface.

The SIOCSIFINFO_IN6 ioctl is missing a necessary permissions check.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-09:10.ipv6.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-09:10.ipv6.asc";


if(description)
{
 script_id(64205);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-06-15 19:20:43 +0200 (Mon, 15 Jun 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "FreeBSD Security Advisory (FreeBSD-SA-09:10.ipv6.asc)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "FreeBSD Security Advisory (FreeBSD-SA-09:10.ipv6.asc)";
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
if(patchlevelcmp(rel:"7.2", patchlevel:"1")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.1", patchlevel:"6")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.4", patchlevel:"5")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.3", patchlevel:"11")<0) {
    vuln = 1;
}

if(vuln) {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
