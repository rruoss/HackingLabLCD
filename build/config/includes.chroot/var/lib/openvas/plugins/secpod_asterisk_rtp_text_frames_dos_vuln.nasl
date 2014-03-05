###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_asterisk_rtp_text_frames_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Asterisk RTP Text Frames Denial Of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_solution = "Upgrade to Asterisk version 1.6.1.2 or latest or apply the patch,
  http://www.asterisk.org/downloads
  http://downloads.asterisk.org/pub/security/AST-2009-004-1.6.1.diff.txt

  *****
  NOTE: Please ignore the warning if the patch is applied.
  *****";

tag_impact = "Successful exploitation will let the attacker cause Denial of Service
  in the victim's system.
  Impact Level: Application";
tag_affected = "Asterisk version 1.6.1 and before 1.6.1.2 on Linux.";
tag_insight = "Error in main/rtp.c file which can be exploited via an RTP text frame without
  a certain delimiter that triggers a NULL pointer dereference and the
  subsequent calculation to an invalid pointer.";
tag_summary = "This host has Asterisk installed and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(900812);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2651");
  script_bugtraq_id(35837);
  script_name("Asterisk RTP Text Frames Denial Of Service Vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36039/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2067");
  script_xref(name : "URL" , value : "http://downloads.asterisk.org/pub/security/AST-2009-004.html");

  script_description(desc);
  script_summary("Check for the Version of Asterisk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_require_keys("Asterisk-PBX/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

asteriskPort = get_kb_item("Services/udp/sip");
if(!asteriskPort)exit(0);
if(!get_udp_port_state(asteriskPort))exit(0);

asteriskVer = get_kb_item("Asterisk-PBX/Ver");
if(!asteriskVer){
  exit(0);
}

# Check for Asterisk version 1.6.1 < 1.6.1.2
if(version_in_range(version:asteriskVer, test_version:"1.6.1",
                                         test_version2:"1.6.1.1")){
  security_warning(port:asteriskPort, proto:"udp");
}
