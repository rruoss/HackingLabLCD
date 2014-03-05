###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ntp_bof_vuln_may09.nasl 15 2013-10-27 12:49:54Z jan $
#
# NTP 'ntpd' Autokey Stack Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker craft a specially malicious
  NTP request packet which can crash ntp daemon or can cause arbitrary code
  execution in the affected machine with local user's privilege.

  Impact level: Application.";

tag_affected = "NTP version prior to 4.2.4p7
  NTP version 4.2.5 to 4.2.5p73";
tag_insight = "This flaw is due to configuration error in ntp daemon's NTPv4
  authentication code. If ntp daemon is configured to use Public Key
  Cryptography for NTP Packet authentication which lets the attacker send
  crafted NTP requests.";
tag_solution = "Apply the security update according to the OS version.
  https://admin.fedoraproject.org/updates/search/ntp";
tag_summary = "This host is running NTP Daemon and is prone to stack overflow vulnerability.";

if(description)
{
  script_id(900652);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1252");
  script_bugtraq_id(35017);
  script_name("NTP 'ntpd' Autokey Stack Overflow Vulnerability");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "https://launchpad.net/bugs/cve/2009-1252");
  script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1040.html");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=499694");

  script_description(desc);
  script_summary("Check for the version of NTP Daemon");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_require_keys("NTP/Linux/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

ntpPort = 123;
if(!get_udp_port_state(ntpPort)){
  exit(0);
}

fullVer = get_kb_item("NTP/Linux/FullVer");
if(fullVer && fullVer == "ntpd 4.2.4p4@1.1520-o Sun Nov 22 17:34:54 UTC 2009 (1)") {
  exit(0); # debian backport
}

ntpVer = get_kb_item("NTP/Linux/Ver");
if(ntpVer == NULL){
  exit(0);
}

if(version_is_less(version:ntpVer, test_version:"4.2.4.p7") ||
   version_in_range(version:ntpVer, test_version:"4.2.5", test_version2:"4.2.5.p73") ||
   version_is_equal(version:ntpVer, test_version:"4.2.4.p7.RC2")){
  security_hole(port:ntpPort, proto:"udp");
}
