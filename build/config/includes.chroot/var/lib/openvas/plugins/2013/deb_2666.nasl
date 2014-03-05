# OpenVAS Vulnerability Test
# $Id: deb_2666.nasl 39 2013-11-04 11:37:28Z mime $
# Auto-generated from advisory DSA 2666-1 using nvtgen 1.0
# Script version: 1.0
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

tag_affected  = "xen on Debian Linux";
tag_insight   = "Xen is a hypervisor providing services that allow multiple computer operating
systems to execute on the same computer hardware concurrently.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 4.0.1-5.11.

For the stable distribution (wheezy), these problems have been fixed in
version 4.1.4-3+deb7u1.

For the testing distribution (jessie), these problems have been fixed in
version 4.1.4-4.

For the unstable distribution (sid), these problems have been fixed in
version 4.1.4-4.

Note that for the stable (wheezy), testing and unstable distribution,
CVE-2013-1964 (XSA
50 
) was already fixed in version 4.1.4-3.

We recommend that you upgrade your xen packages.";
tag_summary   = "Multiple vulnerabilities have been discovered in the Xen hypervisor. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2013-1918 (XSA
45 
) several long latency operations are not preemptible.

Some page table manipulation operations for PV guests were not made
preemptible, allowing a malicious or buggy PV guest kernel to mount a
denial of service attack affecting the whole system.

CVE-2013-1952 (XSA
49 
) VT-d interrupt remapping source validation flaw for bridges.

Due to missing source validation on interrupt remapping table
entries for MSI interrupts set up by bridge devices, a malicious
domain with access to such a device can mount a denial of service
attack affecting the whole system.

CVE-2013-1964 (XSA
50 
) grant table hypercall acquire/release imbalance.

When releasing a particular, non-transitive grant after doing a grant
copy operation, Xen incorrectly releases an unrelated grant
reference, leading possibly to a crash of the host system.
Furthermore information leakage or privilege escalation cannot be
ruled out.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

desc = "Summary:
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
    script_id(892666);
    script_version("$Revision: 39 $");
    script_cve_id("CVE-2013-1952", "CVE-2013-1918", "CVE-2013-1964");
    script_name("Debian Security Advisory DSA 2666-1 (xen - several vulnerabilities");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-04 12:37:28 +0100 (Mo, 04. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-05-12 00:00:00 +0200 (So, 12 Mai 2013)");
    script_tag(name: "cvss_base", value:"6.9");
    script_tag(name: "cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
    script_tag(name: "risk_factor", value:"High");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2666.html");

    script_summary("Debian Security Advisory DSA 2666-1 (xen - several vulnerabilities)");

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
if ((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.0.1-5.11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.0.1-5.11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-docs-4.0", ver:"4.0.1-5.11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-hypervisor-4.0-amd64", ver:"4.0.1-5.11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-hypervisor-4.0-i386", ver:"4.0.1-5.11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-utils-4.0", ver:"4.0.1-5.11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.0.1-5.11", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxen-4.1", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxen-ocaml", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxen-ocaml-dev", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-docs-4.1", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-hypervisor-4.1-amd64", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-hypervisor-4.1-i386", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-system-i386", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-utils-4.1", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.1.4-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
