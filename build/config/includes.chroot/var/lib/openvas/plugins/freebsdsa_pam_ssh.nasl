#
#ADV FreeBSD-SA-11:09.pam_ssh.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-11:09.pam_ssh.asc
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "The PAM (Pluggable Authentication Modules) library provides a flexible
framework for user authentication and session setup / teardown.  It is
used not only in the base system, but also by a large number of
third-party applications.

Various authentication methods (UNIX, LDAP, Kerberos etc.) are
implemented in modules which are loaded and executed according to
predefined, named policies.  These policies are defined in
/etc/pam.conf, /etc/pam.d/<policy name>, /usr/local/etc/pam.conf or
/usr/local/etc/pam.d/<policy name>.

The base system includes a module named pam_ssh which, if enabled,
allows users to authenticate themselves by typing in the passphrase of
one of the SSH private keys which are stored in encrypted form in the
their .ssh directory.  Authentication is considered successful if at
least one of these keys could be decrypted using the provided
passphrase.

By default, the pam_ssh module rejects SSH private keys with no
passphrase.  A nullok option exists to allow these keys.

The OpenSSL library call used to decrypt private keys ignores the
passphrase argument if the key is not encrypted.  Because the pam_ssh
module only checks whether the passphrase provided by the user is
null, users with unencrypted SSH private keys may successfully
authenticate themselves by providing a dummy passphrase.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-11:09.pam_ssh.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-11:09.pam_ssh.asc";


if(description)
{
 script_id(70763);
 script_version("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("FreeBSD Security Advisory (FreeBSD-SA-11:09.pam_ssh.asc)");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-12 07:37:01 -0500 (Sun, 12 Feb 2012)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 script_summary("FreeBSD Security Advisory (FreeBSD-SA-11:09.pam_ssh.asc)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdpatchlevel", "login/SSH/success");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");
vuln = 0;
if(patchlevelcmp(rel:"7.4", patchlevel:"5")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.3", patchlevel:"9")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"8.2", patchlevel:"5")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"8.1", patchlevel:"7")<0) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
