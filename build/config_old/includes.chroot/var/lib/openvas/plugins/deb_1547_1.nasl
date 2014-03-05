# OpenVAS Vulnerability Test
# $Id: deb_1547_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1547-1 (openoffice.org)
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
tag_insight = "Several security related problems have been discovered in
OpenOffice.org, the free office suite.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2007-5745, CVE-2007-5747

Several bugs have been discovered in the way OpenOffice.org parses
Quattro Pro files that may lead to a overflow in the heap
potentially leading to the execution of arbitrary code.

CVE-2007-5746

Specially crafted EMF files can trigger a buffer overflow in the
heap that may lead to the execution of arbitrary code.

CVE-2008-0320

A bug has been discovered in the processing of OLE files that can
cause a buffer overflow in the heap potentially leading to the
execution of arbitrary code.

Recently reported problems in the ICU library are fixed in separate
libicu packages with DSA 1511 against which OpenOffice.org is linked.

For the old stable distribution (sarge) these problems have been fixed in
version 1.1.3-9sarge9.

For the stable distribution (etch) these problems have been fixed in
version 2.0.4.dfsg.2-7etch5.

For the testing (lenny) and unstable (sid) distributions these
problems have been fixed in version 2.4.0~ooh680m5-1.

We recommend that you upgrade your openoffice.org packages.";
tag_summary = "The remote host is missing an update to openoffice.org
announced via advisory DSA 1547-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201547-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(60794);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-04-21 20:40:14 +0200 (Mon, 21 Apr 2008)");
 script_cve_id("CVE-2007-5745", "CVE-2007-5746", "CVE-2007-5747", "CVE-2008-0320");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1547-1 (openoffice.org)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1547-1 (openoffice.org)");

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
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ar", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-en", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-eu", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-gl", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-hi", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-kn", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-mimelnk", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-thesaurus-en-us", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-bin", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-gtk-gnome", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"1.1.3-9sarge9", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"broffice.org", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-common", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-dtd-officedocument1.0", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-filter-mobiledev", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-cs", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-da", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-de", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-dz", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-en-gb", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-en-us", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-en", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-es", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-et", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-fr", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-hi-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-hu", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-it", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-ja", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-km", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-ko", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-nl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-pl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-pt-br", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-ru", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-sl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-sv", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-zh-cn", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-zh-tw", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-as-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-be-by", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-bg", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-bn", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-br", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-bs", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-dz", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-gb", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-za", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-eo", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-fa", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ga", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-gu-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-hi-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-hi", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-hr", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ka", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-km", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ku", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-lo", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-lv", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-mk", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ml-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ne", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nr", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-or-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pa-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-rw", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sr-cs", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ss", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-st", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ta-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-te-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-tg", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ts", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-uk", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ve", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-vi", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-xh", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-za", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-qa-api-tests", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmythes-dev", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-base", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-core", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-dbg", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-filter-so52", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-gtk-gnome", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-math", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-qa-tools", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-uno", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
