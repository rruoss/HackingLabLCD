###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for wireshark CESA-2008:0890 centos3 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Wireshark is a program for monitoring network traffic. Wireshark was
  previously known as Ethereal.

  Multiple buffer overflow flaws were found in Wireshark. If Wireshark read
  a malformed packet off a network, it could crash or, possibly, execute
  arbitrary code as the user running Wireshark. (CVE-2008-3146)
  
  Several denial of service flaws were found in Wireshark. Wireshark could
  crash or stop responding if it read a malformed packet off a network, or
  opened a malformed dump file. (CVE-2008-1070, CVE-2008-1071, CVE-2008-1072,
  CVE-2008-1561, CVE-2008-1562, CVE-2008-1563, CVE-2008-3137, CVE-2008-3138,
  CVE-2008-3141, CVE-2008-3145, CVE-2008-3932, CVE-2008-3933, CVE-2008-3934)
  
  Additionally, this update changes the default Pluggable Authentication
  Modules (PAM) configuration to always prompt for the root password before
  each start of Wireshark. This avoids unintentionally running Wireshark with
  root privileges.
  
  Users of wireshark should upgrade to these updated packages, which contain
  Wireshark version 1.0.3, and resolve these issues.";

tag_affected = "wireshark on CentOS 3";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-October/015281.html");
  script_id(880108);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "CESA", value: "2008:0890");
  script_cve_id("CVE-2008-1070", "CVE-2008-1071", "CVE-2008-1072", "CVE-2008-1561", "CVE-2008-1562", "CVE-2008-1563", "CVE-2008-3137", "CVE-2008-3138", "CVE-2008-3141", "CVE-2008-3145", "CVE-2008-3146", "CVE-2008-3932", "CVE-2008-3933", "CVE-2008-3934");
  script_name( "CentOS Update for wireshark CESA-2008:0890 centos3 i386");

  script_description(desc);
  script_summary("Check for the Version of wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.3~EL3.3", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.0.3~EL3.3", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
