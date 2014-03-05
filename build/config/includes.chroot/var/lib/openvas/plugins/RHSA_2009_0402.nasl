# OpenVAS Vulnerability Test
# $Id: RHSA_2009_0402.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory RHSA-2009:0402 ()
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
tag_summary = "The remote host is missing updates announced in
advisory RHSA-2009:0402.

Openswan is a free implementation of Internet Protocol Security (IPsec)
and Internet Key Exchange (IKE). IPsec uses strong cryptography to provide
both authentication and encryption services. These services allow you to
build secure tunnels through untrusted networks. Everything passing through
the untrusted network is encrypted by the IPsec gateway machine, and
decrypted by the gateway at the other end of the tunnel. The resulting
tunnel is a virtual private network (VPN).

Gerd v. Egidy discovered a flaw in the Dead Peer Detection (DPD) in
Openswan's pluto IKE daemon. A remote attacker could use a malicious DPD
packet to crash the pluto daemon. (CVE-2009-0790)

It was discovered that Openswan's livetest script created temporary files
in an insecure manner. A local attacker could use this flaw to overwrite
arbitrary files owned by the user running the script. (CVE-2008-4190)

Note: The livetest script is an incomplete feature and was not
automatically executed by any other script distributed with Openswan, or
intended to be used at all, as was documented in its man page. In these
updated packages, the script only prints an informative message and exits
immediately when run.

All users of openswan are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After installing
this update, the ipsec service will be restarted automatically.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if(description)
{
 script_id(63711);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
 script_cve_id("CVE-2008-4190", "CVE-2009-0790");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("RedHat Security Advisory RHSA-2009:0402");


 script_description(desc);

 script_summary("Redhat Security Advisory RHSA-2009:0402");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-0402.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#important");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"openswan", rpm:"openswan~2.6.14~1.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openswan-debuginfo", rpm:"openswan-debuginfo~2.6.14~1.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openswan-doc", rpm:"openswan-doc~2.6.14~1.el5_3.2", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
