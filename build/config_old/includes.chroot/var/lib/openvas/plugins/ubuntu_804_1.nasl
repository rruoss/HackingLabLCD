# OpenVAS Vulnerability Test
# $Id: ubuntu_804_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-804-1 (pulseaudio)
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

Ubuntu 8.04 LTS:
  pulseaudio                      0.9.10-1ubuntu1.1

Ubuntu 8.10:
  pulseaudio                      0.9.10-2ubuntu9.4

Ubuntu 9.04:
  pulseaudio                      1:0.9.14-0ubuntu20.2

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-804-1";

tag_insight = "Tavis Ormandy and Yorick Koster discovered that PulseAudio did not
safely re-execute itself.  A local attacker could exploit this to gain
root privileges.";
tag_summary = "The remote host is missing an update to pulseaudio
announced via advisory USN-804-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64445);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-1894");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Ubuntu USN-804-1 (pulseaudio)");


 script_description(desc);

 script_summary("Ubuntu USN-804-1 (pulseaudio)");

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
if ((res = isdpkgvuln(pkg:"libpulse-browse0-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-browse0", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-dev", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-mainloop-glib0-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-mainloop-glib0", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse0-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse0", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulsecore5-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulsecore5", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-esound-compat-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-esound-compat", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-gconf-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-gconf", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-hal-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-hal", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-lirc-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-lirc", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-x11-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-x11", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-zeroconf-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-zeroconf", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-utils-dbg", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-utils", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio", ver:"0.9.10-1ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-browse0-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-browse0", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-dev", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-mainloop-glib0-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-mainloop-glib0", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse0-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse0", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulsecore5-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulsecore5", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-esound-compat-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-esound-compat", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-gconf-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-gconf", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-hal-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-hal", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-lirc-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-lirc", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-x11-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-x11", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-zeroconf-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-zeroconf", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-utils-dbg", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-utils", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio", ver:"0.9.10-2ubuntu9.4", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-browse0-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-browse0", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-dev", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-mainloop-glib0-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse-mainloop-glib0", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse0-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulse0", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulsecore9-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpulsecore9", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-esound-compat-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-esound-compat", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-gconf-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-gconf", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-hal-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-hal", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-lirc-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-lirc", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-x11-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-x11", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-zeroconf-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-module-zeroconf", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-utils-dbg", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio-utils", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pulseaudio", ver:"0.9.14-0ubuntu20.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
