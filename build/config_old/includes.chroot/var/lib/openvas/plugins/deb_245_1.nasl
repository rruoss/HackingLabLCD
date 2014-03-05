# OpenVAS Vulnerability Test
# $Id: deb_245_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 245-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
tag_insight = "Florian Lohoff discovered a bug in the dhcrelay causing it to send a
continuing packet storm towards the configured DHCP server(s) in case
of a malicious BOOTP packet, such as sent from buggy Cisco switches.

When the dhcp-relay receives a BOOTP request it forwards the request
to the DHCP server using the broadcast MAC address ff:ff:ff:ff:ff:ff
which causes the network interface to reflect the packet back into the
socket.  To prevent loops the dhcrelay checks whether the
relay-address is its own, in which case the packet would be dropped.
In combination with a missing upper boundary for the hop counter an
attacker can force the dhcp-relay to send a continuing packet storm
towards the configured dhcp server(s).

This patch introduces a new commandline switch ``-c maxcount'' and
people are advised to start the dhcp-relay with ``dhcrelay -c 10''
or a smaller number, which will only create that many packets.

The dhcrelay program from the ``dhcp'' package does not seem to be
affected since DHCP packets are dropped if they were apparently
relayed already.

For the stable distribution (woody) this problem has been fixed in
version 3.0+3.0.1rc9-2.2.

The old stable distribution (potato) does not contain dhcp3 packages.

For the unstable distribution (sid) this problem has been fixed in
version 1.1.2-1.

We recommend that you upgrade your dhcp3 package when you are using";
tag_summary = "The remote host is missing an update to dhcp3
announced via advisory DSA 245-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20245-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53321);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(6628);
 script_cve_id("CVE-2003-0039");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 245-1 (dhcp3)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 245-1 (dhcp3)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.0+3.0.1rc9-2.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-common", ver:"3.0+3.0.1rc9-2.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"3.0+3.0.1rc9-2.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"3.0+3.0.1rc9-2.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server", ver:"3.0+3.0.1rc9-2.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
