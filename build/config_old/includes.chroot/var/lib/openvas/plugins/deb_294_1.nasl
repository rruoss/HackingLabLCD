# OpenVAS Vulnerability Test
# $Id: deb_294_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 294-1
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
tag_insight = "Brian Campbell discovered two security-related problems in
gkrellm-newsticker, a plugin for the gkrellm system monitor program,
which provides a news ticker from RDF feeds.  The Common
Vulnerabilities and Exposures project identifies the following
problems:

CVE-2003-0205

It can launch a web browser of the user's choice when the ticker
title is clicked by using the URI given by the feed.  However,
special shell characters are not properly escaped enabling a
malicious feed to execute arbitrary shell commands on the clients
machine.

CVE-2003-0206

It crashes the entire gkrellm system on feeds where link or title
elements are not entirely on a single line.  A malicious server
could therefore craft a denial of service.

For the stable distribution (woody) these problems have been fixed in
version 0.3-3.1

The old stable distribution (potato) is not affected since it doesn't
contain gkrellm-newsticker packages.

For the unstable distribution (sid) these problems is not yet fixed.

We recommend that you upgrade your gkrellm-newsticker package.";
tag_summary = "The remote host is missing an update to gkrellm-newsticker
announced via advisory DSA 294-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20294-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53366);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0205", "CVE-2003-0206");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 294-1 (gkrellm-newsticker)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 294-1 (gkrellm-newsticker)");

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
if ((res = isdpkgvuln(pkg:"gkrellm-newsticker", ver:"0.3-3.1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
