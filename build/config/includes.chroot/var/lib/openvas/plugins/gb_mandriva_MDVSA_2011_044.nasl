###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for wireshark MDVSA-2011:044 (wireshark)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "This advisory updates wireshark to the latest version (1.2.15),
  fixing several security issues:

  Wireshark 1.5.0, 1.4.3, and earlier frees an uninitialized pointer
  during processing of a .pcap file in the pcap-ng format, which allows
  remote attackers to cause a denial of service (memory corruption)
  or possibly have unspecified other impact via a malformed file
  (CVE-2011-0538).
  
  Heap-based buffer overflow in wiretap/dct3trace.c in Wireshark
  1.2.0 through 1.2.14 and 1.4.0 through 1.4.3 allows remote attackers
  to cause a denial of service (application crash) or possibly have
  unspecified other impact via a long record in a Nokia DCT3 trace file
  (CVE-2011-0713).
  
  wiretap/pcapng.c in Wireshark 1.2.0 through 1.2.14 and 1.4.0 through
  1.4.3 allows remote attackers to cause a denial of service (application
  crash) via a pcap-ng file that contains a large packet-length field
  (CVE-2011-1139).
  
  Multiple stack consumption vulnerabilities in the
  dissect_ms_compressed_string and dissect_mscldap_string functions in
  Wireshark 1.0.x, 1.2.0 through 1.2.14, and 1.4.0 through 1.4.3 allow
  remote attackers to cause a denial of service (infinite recursion)
  via a crafted (1) SMB or (2) Connection-less LDAP (CLDAP) packet
  (CVE-2011-1140).
  
  epan/dissectors/packet-ldap.c in Wireshark 1.0.x, 1.2.0 through 1.2.14,
  and 1.4.0 through 1.4.3 allows remote attackers to cause a denial
  of service (memory consumption) via (1) a long LDAP filter string or
  (2) an LDAP filter string containing many elements (CVE-2011-1141).
  
  Stack consumption vulnerability in the dissect_ber_choice function in
  the BER dissector in Wireshark 1.2.x through 1.2.15 and 1.4.x through
  1.4.4 might allow remote attackers to cause a denial of service
  (infinite loop) via vectors involving self-referential ASN.1 CHOICE
  values (CVE-2011-1142).
  
  The updated packages have been upgraded to the latest 1.2.x version
  (1.2.15) and patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "wireshark on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2011-03/msg00006.php");
  script_id(831345);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-15 14:58:18 +0100 (Tue, 15 Mar 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDVSA", value: "2011:044");
  script_cve_id("CVE-2011-0538", "CVE-2011-0713", "CVE-2011-1139", "CVE-2011-1140", "CVE-2011-1141", "CVE-2011-1142");
  script_name("Mandriva Update for wireshark MDVSA-2011:044 (wireshark)");

  script_description(desc);
  script_summary("Check for the Version of wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
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

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~1.2.15~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark0", rpm:"libwireshark0~1.2.15~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~1.2.15~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~1.2.15~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tshark", rpm:"tshark~1.2.15~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.2.15~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~1.2.15~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark0", rpm:"lib64wireshark0~1.2.15~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~1.2.15~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~1.2.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark0", rpm:"libwireshark0~1.2.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~1.2.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~1.2.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tshark", rpm:"tshark~1.2.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.2.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~1.2.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark0", rpm:"lib64wireshark0~1.2.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~1.2.15~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark0", rpm:"libwireshark0~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tshark", rpm:"tshark~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark0", rpm:"lib64wireshark0~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
