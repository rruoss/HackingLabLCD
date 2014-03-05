# OpenVAS Vulnerability Test
# $Id: deb_2458_2.nasl 18 2013-10-27 14:14:13Z jan $
# Auto-generated from advisory DSA 2458-2 using nvtgen 1.0
# Script version: 2.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the Free
# Software Foundation
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

tag_affected  = "iceape on Debian Linux";
tag_insight   = "The Iceape Internet Suite is an unbranded Seamonkey Internet Suite suitable
for free distribution. The Seamonkey Internet Suite is a set of Internet
oriented applications. It is the continuity of the Mozilla Suite after it
has been abandoned in favor of Firefox and Thunderbird.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 2.0.11-12

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your iceape packages.";
tag_summary   = "Several vulnerabilities have been found in the Iceape internet suite,
an unbranded version of Seamonkey:

CVE-2012-0455Soroush Dalili discovered that a cross-site scripting countermeasure
related to JavaScript URLs could be bypassed.

CVE-2012-0456Atte Kettunen discovered an out of bounds read in the SVG Filters,
resulting in memory disclosure.

CVE-2012-0458Mariusz Mlynski discovered that privileges could be escalated through
a JavaScript URL as the home page.

CVE-2012-0461Bob Clary discovered memory corruption bugs, which may lead to the
execution of arbitrary code.

CVE-2012-0467Bob Clary, Christian Holler, Brian Hackett, Bobby Holley, Gary
Kwong, Hilary Hall, Honza Bambas, Jesse Ruderman, Julian Seward,
and Olli Pettay discovered memory corruption bugs, which may lead
to the execution of arbitrary code.

CVE-2012-0470Atte Kettunen discovered that a memory corruption bug in
gfxImageSurface may lead to the execution of arbitrary code.

CVE-2012-0471Anne van Kesteren discovered that incorrect multibyte character
encoding may lead to cross-site scripting.

CVE-2012-0477Masato Kinugawa discovered that incorrect encoding of
Korean and Chinese character sets may lead to cross-site scripting.

CVE-2012-0479Jeroen van der Gun discovered a spoofing vulnerability in the
presentation of Atom and RSS feeds over HTTPS.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
    script_id(892458);
    script_version("$Revision: 18 $");
    script_cve_id("CVE-2012-0477", "CVE-2012-0458", "CVE-2012-0471", "CVE-2012-0479", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0461", "CVE-2012-0470", "CVE-2012-0467");
    script_name("Debian Security Advisory DSA 2458-2 (iceape - several vulnerabilities");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
    script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
    script_tag(name: "cvss_base", value:"10.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name: "risk_factor", value:"Critical");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2012/dsa-2458.html");

    script_summary("Debian Security Advisory DSA 2458-2 (iceape - several vulnerabilities)");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
        script_tag(name: "affected",  value: tag_affected);
        script_tag(name: "insight",   value: tag_insight);
#        script_tag(name: "impact",    value: tag_impact);
        script_tag(name: "solution",  value: tag_solution);
        script_tag(name: "summary",   value: tag_summary);
        script_tag(name: "vuldetect", value: tag_vuldetect);
    }

    exit(0);
}

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"iceape", ver:"2.0.11-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-browser", ver:"2.0.11-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-chatzilla", ver:"2.0.11-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-dbg", ver:"2.0.11-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-dev", ver:"2.0.11-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-mailnews", ver:"2.0.11-1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
