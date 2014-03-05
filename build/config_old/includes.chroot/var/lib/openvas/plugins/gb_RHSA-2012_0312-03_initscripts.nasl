###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for initscripts RHSA-2012:0312-03
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "The initscripts package contains system scripts to boot your system, change
  runlevels, activate and deactivate most network interfaces, and shut the
  system down cleanly.

  With the default IPsec (Internet Protocol Security) ifup script
  configuration, the racoon IKE key management daemon used aggressive IKE
  mode instead of main IKE mode. This resulted in the preshared key (PSK)
  hash being sent unencrypted, which could make it easier for an attacker
  able to sniff network traffic to obtain the plain text PSK from a
  transmitted hash. (CVE-2008-1198)

  Red Hat would like to thank Aleksander Adamowski for reporting this issue.

  This update also fixes the following bugs:

  * Prior to this update, the DHCPv6 client was not terminated when the
  network service was stopped. This update modifies the source so that the
  client is now terminated when stopping the network service. (BZ#568896)

  * Prior to this update, on some systems the rm command failed and reported
  the error message &quot;rm: cannot remove directory `/var/run/dovecot/login/':
  Is a directory&quot; during system boot. This update modifies the source so that
  this error message no longer appears. (BZ#679998)

  * Prior to this update, the netconsole script could not discover and
  resolve the MAC address of the router specified in the
  /etc/sysconfig/netconsole file. This update modifies the netconsole script
  so that the script no longer fails when the arping tool returns the MAC
  address of the router more than once. (BZ#744734)

  * Prior to this update, the arp_ip_target was, due to a logic error, not
  correctly removed via sysfs. As a consequence, the error &quot;ifdown-eth: line
  64: echo: write error: Invalid argument&quot; was reported when attempting to
  shut down a bonding device. This update modifies the script so that the
  error no longer appears and arp_ip_target is now correctly removed.
  (BZ#745681)

  All users of initscripts are advised to upgrade to this updated package,
  which fixes these issues.";

tag_affected = "initscripts on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-February/msg00043.html");
  script_id(870555);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:56:47 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2008-1198");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "RHSA", value: "2012:0312-03");
  script_name("RedHat Update for initscripts RHSA-2012:0312-03");

  script_description(desc);
  script_summary("Check for the Version of initscripts");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"initscripts", rpm:"initscripts~8.45.42~1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"initscripts-debuginfo", rpm:"initscripts-debuginfo~8.45.42~1.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}