###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for samba FEDORA-2013-1716
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_affected = "samba on Fedora 16";
tag_insight = "Samba is the suite of programs by which a lot of PC-related machines
  share files, printers, and other information (such as lists of
  available files and printers). The Windows NT, OS/2, and Linux
  operating systems support this natively, and add-on packages can
  enable the same thing for DOS, Windows, VMS, UNIX of all kinds, MVS,
  and more. This package provides an SMB/CIFS server that can be used to
  provide network services to SMB/CIFS clients.
  Samba uses NetBIOS over TCP/IP (NetBT) protocols and does NOT
  need the NetBEUI (Microsoft Raw NetBIOS frame) protocol.";
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
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-February/098623.html");
  script_id(865347);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-15 11:13:44 +0530 (Fri, 15 Feb 2013)");
  script_cve_id("CVE-2013-0213", "CVE-2013-0214", "CVE-2012-2111", "CVE-2012-1182",
                "CVE-2012-0817");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "FEDORA", value: "2013-1716");
  script_name("Fedora Update for samba FEDORA-2013-1716");

  script_description(desc);
  script_summary("Check for the Version of samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.6.12~1.fc16", rls:"FC16")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}