###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openswan CESA-2013:0827 centos5
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
tag_insight = "Openswan is a free implementation of Internet Protocol Security (IPsec)
  and Internet Key Exchange (IKE). IPsec uses strong cryptography to provide
  both authentication and encryption services. These services allow you to
  build secure tunnels through untrusted networks. When using Opportunistic
  Encryption, Openswan's pluto IKE daemon requests DNS TXT records to obtain
  public RSA keys of itself and its peers.

  A buffer overflow flaw was found in Openswan. If Opportunistic Encryption
  were enabled (/etc/ipsec.conf) and an RSA key configured, an
  attacker able to cause a system to perform a DNS lookup for an
  attacker-controlled domain containing malicious records (such as by sending
  an email that triggers a DKIM or SPF DNS record lookup) could cause
  Openswan's pluto IKE daemon to crash or, potentially, execute arbitrary
  code with root privileges. With but no RSA key configured, the
  issue can only be triggered by attackers on the local network who can
  control the reverse DNS entry of the target system. Opportunistic
  Encryption is disabled by default. (CVE-2013-2053)

  This issue was discovered by Florian Weimer of the Red Hat Product Security
  Team.

  All users of openswan are advised to upgrade to these updated packages,
  which contain backported patches to correct this issue. After installing
  this update, the ipsec service will be restarted automatically.";


tag_affected = "openswan on CentOS 5";
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
  script_id(881728);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-17 09:51:58 +0530 (Fri, 17 May 2013)");
  script_cve_id("CVE-2013-2053");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("CentOS Update for openswan CESA-2013:0827 centos5 ");

  script_description(desc);
  script_xref(name: "CESA", value: "2013:0827");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-May/019730.html");
  script_summary("Check for the Version of openswan");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"openswan", rpm:"openswan~2.6.32~5.el5_9", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openswan-doc", rpm:"openswan-doc~2.6.32~5.el5_9", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
