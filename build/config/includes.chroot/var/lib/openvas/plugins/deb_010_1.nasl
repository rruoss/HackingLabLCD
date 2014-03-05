# OpenVAS Vulnerability Test
# $Id: deb_010_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 010-1
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
tag_insight = "Two bugs in GnuPG have recently been found:

1. false positives when verifying detached signatures
- -----------------------------------------------------

There is a problem in the way gpg checks detached signatures which
can lead to false positives. Detached signature can be verified
with a command like this:

gpg --verify detached.sig < mydata

If someone replaced detached.sig with a signed text (ie not a
detached signature) and then modified mydata gpg would still
report a successfully verified signature.

To fix the way the --verify option works has been changes: it now
needs two options when verifying detached signatures: both the file
with the detached signature, and the file with the data to be
verified. Please note that this makes it incompatible with older
versions!

2. secret keys are silently imported
- ------------------------------------

Florian Weimer discovered that gpg would import secret keys from
key-servers. Since gpg considers public keys corresponding to
known secret keys to be ultimately trusted an attacked can use this
circumvent the web of trust.

To fix this a new option was added to to tell gpg it is allowed
to import secret keys: --allow-key-import.


Both these fixes are in version 1.0.4-1.1 and we recommend that you
upgrade your gnupg package immediately.";
tag_summary = "The remote host is missing an update to gnupg
announced via advisory DSA 010-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20010-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53861);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 010-1 (gnupg)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 010-1 (gnupg)");

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
if ((res = isdpkgvuln(pkg:"gnupg", ver:"1.0.4-1.1", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
