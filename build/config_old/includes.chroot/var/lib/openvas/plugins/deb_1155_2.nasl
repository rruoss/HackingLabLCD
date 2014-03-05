# OpenVAS Vulnerability Test
# $Id: deb_1155_2.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1155-2
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
tag_solution = "For the stable distribution (sarge) this problem has been fixed in
version 8.13.4-3sarge2.

For the unstable distribution (sid) this problem has been fixed in
version 8.13.7-1.

We recommend that you upgrade your sendmail package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201155-2";
tag_summary = "The remote host is missing an update to sendmail
announced via advisory DSA 1155-2.

It turned out that the sendmail binary depends on libsasl2 (>= 2.1.19.dfsg1)
which is neither available in the stable nor in the the security archive.
This version is scheduled for the inclusion in the next update of the
stable release, though.

You'll have to download the referenced file for your architecture from
below and install it with dpkg -i.

As an alternative, temporarily adding the following line to
/etc/apt/sources.list will mitigate the problem as well:

deb http://ftp.debian.de/debian stable-proposed-updates main

Here is the original security advisory for completeness:

Frank Sheiness discovered that a MIME conversion routine in sendmail,
a powerful, efficient, and scalable mail transport agent, could be
tricked by a specially crafted mail to perform an endless recursion.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(57300);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-1173");
 script_bugtraq_id(18433);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1155-2 (sendmail)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1155-2 (sendmail)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"libsasl2", ver:"2.1.19.dfsg1-0sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
