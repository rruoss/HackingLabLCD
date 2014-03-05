# OpenVAS Vulnerability Test
# $Id: ubuntu_697_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory USN-697-1 (imlib2)
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  libimlib2                       1.2.1-2ubuntu0.4

Ubuntu 7.10:
  libimlib2                       1.3.0.0debian1-4ubuntu0.2

Ubuntu 8.04 LTS:
  libimlib2                       1.4.0-1ubuntu1.2

After a standard system upgrade you need to restart any applications that
use Imlib2 to effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-697-1";

tag_insight = "It was discovered that Imlib2 did not correctly handle certain malformed XPM
and PNG images. If a user were tricked into opening a specially crafted image
with an application that uses Imlib2, an attacker could cause a denial of
service and possibly execute arbitrary code with the user's privileges.";
tag_summary = "The remote host is missing an update to imlib2
announced via advisory USN-697-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63073);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-12-29 22:42:24 +0100 (Mon, 29 Dec 2008)");
 script_cve_id("CVE-2008-2426", "CVE-2008-2434", "CVE-2008-5027", "CVE-2008-4242", "CVE-2007-3372", "CVE-2008-5081", "CVE-2008-4577", "CVE-2008-4870", "CVE-2008-5140", "CVE-2008-5312", "CVE-2008-5313", "CVE-2008-4844", "CVE-2008-2237", "CVE-2008-2238", "CVE-2008-4937");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-697-1 (imlib2)");


 script_description(desc);

 script_summary("Ubuntu USN-697-1 (imlib2)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libimlib2-dev", ver:"1.2.1-2ubuntu0.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libimlib2", ver:"1.2.1-2ubuntu0.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libimlib2-dev", ver:"1.3.0.0debian1-4ubuntu0.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libimlib2", ver:"1.3.0.0debian1-4ubuntu0.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libimlib2-dev", ver:"1.4.0-1ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libimlib2", ver:"1.4.0-1ubuntu1.2", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios-common", ver:"1.3-cvs.20050402-8ubuntu8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios-mysql", ver:"1.3-cvs.20050402-8ubuntu8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios-pgsql", ver:"1.3-cvs.20050402-8ubuntu8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios-text", ver:"1.3-cvs.20050402-8ubuntu8", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.3.0-19etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-ldap", ver:"1.3.0-19etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-mysql", ver:"1.3.0-19etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd-pgsql", ver:"1.3.0-19etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"proftpd", ver:"1.3.0-19etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-discover", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-avahi", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-core4", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-howl0", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-common-data", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt3-1", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt4-dev", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-client-dev", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-libdnssd-dev", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-dnsconfd", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-glib1", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-common3", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-core-dev", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt4-1", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-qt3-dev", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-client3", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-howl-dev", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-compat-libdnssd1", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-glib-dev", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavahi-common-dev", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-utils", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"avahi-autoipd", ver:"0.6.16-3etch2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-br", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-cs", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-da", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-de", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-dz", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-en-gb", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-en-us", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-es", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-et", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-eu", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-fr", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-gl", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-hi-in", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-hu", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-it", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-ja", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-km", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-ko", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-nl", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-pl", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-pt-br", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-pt", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-ru", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-sl", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-sv", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-zh-cn", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-help-zh-tw", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ar", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-as-in", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-be-by", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-bg", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-bn", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-br", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-bs", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-common", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-dz", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-gb", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-en-za", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-eo", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-eu", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-fa", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ga", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-gl", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-gu-in", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-hi-in", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-hr", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ka", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-km", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-kn", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ku", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-lo", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-lv", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-mk", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ml-in", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-mr-in", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ne", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-nr", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-or-in", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pa-in", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ro", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-rw", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sr", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ss", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-st", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-sw", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ta-in", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-te-in", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-tg", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ti-er", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ts", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-uk", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ur-in", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-uz", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-ve", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-vi", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-xh", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"2.4.1-1ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}