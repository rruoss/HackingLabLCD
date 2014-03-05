# OpenVAS Vulnerability Test
# $Id: deb_1544_2.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1544-2 (pdns-recursor)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
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
tag_insight = "Thomas Biege discovered that the upstream fix for the weak random number
generator released in DSA-1544-1 was incomplete:  Source port
randomization did still not use difficult-to-predict random numbers.
This is corrected in this security update.

Here is the text of the original advisory:

Amit Klein discovered that pdns-recursor, a caching DNS resolver, uses
a weak random number generator to create DNS transaction IDs and UDP
source port numbers. As a result, cache poisoning attacks were
simplified. (CVE-2008-1637)

In the light of recent DNS-related developments (documented in DSAs
1603, 1604, 1605), we recommend that this update is installed as an
additional safety measure.  (The lack of source port randomization was
addressed in the 3.1.6 upstream version.)

In addition, this update incorporates the changed IP address of
L.ROOT-SERVERS.NET.

For the stable distribution (etch), this problem has been fixed in
version 3.1.4-1+etch2.

For the unstable distribution (sid), this problem has been fixed in
version 3.1.7-1.

We recommend that you upgrade your pdns-recursor package.";
tag_summary = "The remote host is missing an update to pdns-recursor
announced via advisory DSA 1544-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201544-2";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(61360);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-15 15:52:52 +0200 (Fri, 15 Aug 2008)");
 script_cve_id("CVE-2008-1637");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1544-2 (pdns-recursor)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1544-2 (pdns-recursor)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"pdns-recursor", ver:"3.1.4-1+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
