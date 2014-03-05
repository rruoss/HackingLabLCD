#
#ADV FreeBSD-SA-06:09.openssh.asc
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
tag_insight = "OpenSSH is an implementation of the SSH protocol suite, providing an
encrypted, authenticated transport for a variety of services,
including remote shell access.

Privilege separation is a mechanism used by OpenSSH to protect itself
against possible future vulnerabilities.  It works by splitting the
server process in two: the child process drops its privileges and
carries on the conversation with the client, while the parent retains
its privileges, monitors the child, and performs privileged operations
on behalf of the child when it is satisified that everything is in
order.  Privilege separation is enabled by default in FreeBSD.

OpenPAM is an implementation of the PAM framework, which allows the
use of loadable modules to implement user authentication and session
management in a manner defined by the administrator.  It is used by
OpenSSH and numerous other applications in FreeBSD to provide a
consistent and configurable authentication system.

Because OpenSSH and OpenPAM have conflicting designs (one is event-
driven while the other is callback-driven), it is necessary for
OpenSSH to fork a child process to handle calls to the PAM framework.
However, if the unprivileged child terminates while PAM authentication
is under way, the parent process incorrectly believes that the PAM
child also terminated.  The parent process then terminates, and the
PAM child is left behind.

Due to the way OpenSSH performs internal accounting, these orphaned
PAM children are counted as pending connections by the master OpenSSH
server process.  Once a certain number of orphans has accumulated, the
master decides that it is overloaded and stops accepting client
connections.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-06:09.openssh.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-06:09.openssh.asc";

                                                                                
if(description)
{
 script_id(56352);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_bugtraq_id(16892);
 script_cve_id("CVE-2006-0883");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "FreeBSD Security Advisory (FreeBSD-SA-06:09.openssh.asc)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "FreeBSD Security Advisory (FreeBSD-SA-06:09.openssh.asc)";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
if(patchlevelcmp(rel:"5.4", patchlevel:"12")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"27")<0) {
    vuln = 1;
}

if(vuln) {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
