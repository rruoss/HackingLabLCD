# OpenVAS Vulnerability Test
# $Id: ubuntu_799_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory USN-799-1 (dbus)
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
  libdbus-1-2                     0.60-6ubuntu8.4

Ubuntu 8.04 LTS:
  libdbus-1-3                     1.1.20-1ubuntu3.3

Ubuntu 8.10:
  libdbus-1-3                     1.2.4-0ubuntu1.1

Ubuntu 9.04:
  libdbus-1-3                     1.2.12-0ubuntu2.1

After a standard system upgrade you need to reboot your computer to
effect the necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-799-1";

tag_insight = "It was discovered that the D-Bus library did not correctly validate
signatures. If a local user sent a specially crafted D-Bus key, they could
spoof a valid signature and bypass security policies.";
tag_summary = "The remote host is missing an update to dbus
announced via advisory USN-799-1.";

                                                                                

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64441);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-1189", "CVE-2009-2347", "CVE-2009-1890", "CVE-2009-1891", "CVE-2008-2327", "CVE-2009-2285", "CVE-2009-2295", "CVE-2009-0858", "CVE-2009-2334", "CVE-2009-2335", "CVE-2009-2336", "CVE-2008-0196", "CVE-2009-2360", "CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0652", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0776", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1307", "CVE-2009-1832", "CVE-2009-1392", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1841", "CVE-2009-1185", "CVE-2009-0034", "CVE-2009-0037", "CVE-2009-1422", "CVE-2009-1423", "CVE-2009-1424", "CVE-2009-1425", "CVE-2009-1959");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Ubuntu USN-799-1 (dbus)");


 script_description(desc);

 script_summary("Ubuntu USN-799-1 (dbus)");

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
if ((res = isdpkgvuln(pkg:"dbus-1-doc", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-cil", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"monodoc-dbus-1-manual", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-1-utils", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-2", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-dev", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-glib-1-2", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-glib-1-dev", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-qt-1-1c2", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-qt-1-dev", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.4-dbus", ver:"0.60-6ubuntu8.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-1-doc", ver:"1.1.20-1ubuntu3.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-x11", ver:"1.1.20-1ubuntu3.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus", ver:"1.1.20-1ubuntu3.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.1.20-1ubuntu3.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-dev", ver:"1.1.20-1ubuntu3.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-1-doc", ver:"1.2.4-0ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-x11", ver:"1.2.4-0ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus", ver:"1.2.4-0ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.2.4-0ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-dev", ver:"1.2.4-0ubuntu1.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-1-doc", ver:"1.2.12-0ubuntu2.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus-x11", ver:"1.2.12-0ubuntu2.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbus", ver:"1.2.12-0ubuntu2.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-3", ver:"1.2.12-0ubuntu2.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdbus-1-dev", ver:"1.2.12-0ubuntu2.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.7.4-1ubuntu3.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.7.4-1ubuntu3.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.7.4-1ubuntu3.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.7.4-1ubuntu3.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.7.4-1ubuntu3.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.8.2-7ubuntu3.4", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.8.2-7ubuntu3.4", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.8.2-7ubuntu3.4", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.8.2-7ubuntu3.4", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.8.2-7ubuntu3.4", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-doc", ver:"3.8.2-11ubuntu0.8.10.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.8.2-11ubuntu0.8.10.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.8.2-11ubuntu0.8.10.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.8.2-11ubuntu0.8.10.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.8.2-11ubuntu0.8.10.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.8.2-11ubuntu0.8.10.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-doc", ver:"3.8.2-11ubuntu0.9.04.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.8.2-11ubuntu0.9.04.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.8.2-11ubuntu0.9.04.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.8.2-11ubuntu0.9.04.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.8.2-11ubuntu0.9.04.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.8.2-11ubuntu0.9.04.3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-common", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapr0-dev", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapr0", ver:"2.0.55-4ubuntu2.6", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-src", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.8-1ubuntu0.10", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-src", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.9-7ubuntu3.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-src", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.11-2ubuntu2.2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcamlimages-ocaml-doc", ver:"2.2.0-4+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcamlimages-ocaml-dev", ver:"2.2.0-4+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcamlimages-ocaml", ver:"2.2.0-4+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnscache-run", ver:"1.05-4+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"djbdns", ver:"1.05-4+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dbndns", ver:"1.05-4+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sork-passwd-h3", ver:"3.0-2+lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove", ver:"2.0.0.22-0lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dbg", ver:"2.0.0.22-0lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-gnome-support", ver:"2.0.0.22-0lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dev", ver:"2.0.0.22-0lenny1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irssi-dev", ver:"0.8.10-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irssi-text", ver:"0.8.10-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.10-1ubuntu1.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irssi-dev", ver:"0.8.12-3ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.12-3ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irssi-dev", ver:"0.8.12-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.12-4ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irssi-dev", ver:"0.8.12-6ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.12-6ubuntu1.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
