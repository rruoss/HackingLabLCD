# OpenVAS Vulnerability Test
# $Id: deb_075_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 075-1
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
tag_insight = "The telnet daemon contained in the netkit-telnet-ssl_0.16.3-1 package in
the 'stable' (potato) distribution of Debian GNU/Linux is vulnerable to an
exploitable overflow in its output handling.
The original bug was found by <scut@nb.in-berlin.de>, and announced to
bugtraq on Jul 18 2001. At that time, netkit-telnet versions after 0.14 were
not believed to be vulnerable.
On Aug 10 2001, zen-parse posted an advisory based on the same problem, for
all netkit-telnet versions below 0.17.
More details can be found on http://www.securityfocus.com/archive/1/203000 .
As Debian uses the 'telnetd' user to run in.telnetd, this is not a remote
root compromise on Debian systems; the 'telnetd' user can be compromised.

We strongly advise you update your netkit-telnet-ssl packages to the versions
listed below.";
tag_summary = "The remote host is missing an update to netkit-telnet-ssl
announced via advisory DSA 075-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20075-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53824);
 script_cve_id("CVE-2001-0554");
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 075-1 (netkit-telnet-ssl)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 075-1 (netkit-telnet-ssl)");

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
if ((res = isdpkgvuln(pkg:"ssltelnet", ver:"0.16.3-1.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"telnet-ssl", ver:"0.16.3-1.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"telnetd-ssl", ver:"0.16.3-1.1", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
