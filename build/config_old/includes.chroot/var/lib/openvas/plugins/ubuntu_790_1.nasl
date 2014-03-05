# OpenVAS Vulnerability Test
# $Id: ubuntu_790_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-790-1 (cyrus-sasl2)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  libsasl2                        2.1.19.dfsg1-0.1ubuntu3.1

Ubuntu 8.04 LTS:
  libsasl2-2                      2.1.22.dfsg1-18ubuntu2.1

Ubuntu 8.10:
  libsasl2-2                      2.1.22.dfsg1-21ubuntu2.1

Ubuntu 9.04:
  libsasl2-2                      2.1.22.dfsg1-23ubuntu3.1

After a standard system upgrade you need to restart services using SASL
to effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-790-1";

tag_insight = "James Ralston discovered that the Cyrus SASL base64 encoding function
could be used unsafely.  If a remote attacker sent a specially crafted
request to a service that used SASL, it could lead to a loss of privacy,
or crash the application, resulting in a denial of service.";
tag_summary = "The remote host is missing an update to cyrus-sasl2
announced via advisory USN-790-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64319);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
 script_cve_id("CVE-2009-0688");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Ubuntu USN-790-1 (cyrus-sasl2)");


 script_description(desc);

 script_summary("Ubuntu USN-790-1 (cyrus-sasl2)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-heimdal", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-dbg", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-dbg", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-dbg", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
