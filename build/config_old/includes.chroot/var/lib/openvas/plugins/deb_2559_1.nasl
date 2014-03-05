# OpenVAS Vulnerability Test
# $Id: deb_2559_1.nasl 12 2013-10-27 11:15:33Z jan $
# Description: Auto-generated from advisory DSA 2559-1 (libexif)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_insight = "Several vulnerabilities were found in libexif, a library used to parse EXIF
meta-data on camera files.

CVE-2012-2812: A heap-based out-of-bounds array read in the
exif_entry_get_value function allows remote attackers to cause a denial of
service or possibly obtain potentially sensitive information from process
memory via an image with crafted EXIF tags.

CVE-2012-2813: A heap-based out-of-bounds array read in the
exif_convert_utf16_to_utf8 function allows remote attackers to cause a denial
of service or possibly obtain potentially sensitive information from process
memory via an image with crafted EXIF tags.

CVE-2012-2814: A buffer overflow in the exif_entry_format_value function
allows remote attackers to cause a denial of service or possibly execute
arbitrary code via an image with crafted EXIF tags.

CVE-2012-2836: A heap-based out-of-bounds array read in the
exif_data_load_data function allows remote attackers to cause a denial of
service or possibly obtain potentially sensitive information from process
memory via an image with crafted EXIF tags.

CVE-2012-2837: A divide-by-zero error in the mnote_olympus_entry_get_value
function while formatting EXIF maker note tags allows remote attackers to
cause a denial of service via an image with crafted EXIF tags.

CVE-2012-2840: An off-by-one error in the exif_convert_utf16_to_utf8 function
allows remote attackers to cause a denial of service or possibly execute
arbitrary code via an image with crafted EXIF tags.

CVE-2012-2841: An integer underflow in the exif_entry_get_value function can
cause a heap overflow and potentially arbitrary code execution while
formatting an EXIF tag, if the function is called with a buffer size
parameter equal to zero or one.

For the stable distribution (squeeze), these problems have been fixed in
version 0.6.19-1+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in
version 0.6.20-3.

For the unstable distribution (sid), these problems have been fixed in
version 0.6.20-3.

We recommend that you upgrade your libexif packages.";
tag_summary = "The remote host is missing an update to libexif
announced via advisory DSA 2559-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202559-1";

desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(72499);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836", "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
 script_tag(name:"risk_factor", value:"High");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-10-22 08:42:32 -0400 (Mon, 22 Oct 2012)");
 script_name("Debian Security Advisory DSA 2559-1 (libexif)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2559-1 (libexif)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
if((res = isdpkgvuln(pkg:"libexif-dev", ver:"0.6.19-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.19-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libexif-dev", ver:"0.6.20-3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libexif12", ver:"0.6.20-3", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}