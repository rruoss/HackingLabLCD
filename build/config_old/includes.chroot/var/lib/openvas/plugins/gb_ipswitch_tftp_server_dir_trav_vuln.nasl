###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipswitch_tftp_server_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Ipswitch TFTP Server Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to read arbitrary files on the
  affected application.
  Impact Level: Application";
tag_affected = "Ipswitch TFTP Server Version 1.0.0.24 and prior";
tag_insight = "The flaw is due to an error while handling certain requests containing
  'dot dot' sequences (..), which can be exploited to download arbitrary files
  from the host system.";
tag_solution = "No solution or patch is available as of 06th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ipswitch.com/";
tag_summary = "The host is running Ipswitch TFTP Server and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_id(802405);
  script_version("$Revision: 13 $");
  script_bugtraq_id(50890);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-06 11:57:11 +0530 (Tue, 06 Dec 2011)");
  script_name("Ipswitch TFTP Server Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=424");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18189/");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SecPod_Ipswitch_TFTP_Server_Dir_Trav.txt");
  script_xref(name : "URL" , value : "http://secpod.org/exploits/SecPod_Ipswitch_TFTP_Server_Dir_Trav_POC.py");

  script_description(desc);
  script_summary("Check for the directory traversal attack in Ipswitch TFTP Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Remote file access");
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

##
## The script code starts here
##

include("tftp.inc");
include("network_func.inc");

## Check for tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check UDP port status as get_udp_port_state() not working properly
if(!check_udp_port_status(dport:port)){
  exit(0);
}

## list the possible files
foreach file (make_list("windows/win.ini", "winnt/win.ini", "boot.ini"))
{
  ## Construct the attack request
  response = tftp_get(port:port, path:crap(data:"../", length:6*9) + file);

  ## Check The response and confirm the exploit
  if("; for 16-bit app support" >< response || "\WINDOWS" >< response)
  {
    security_warning(port:port);
    exit(0);
  }
}
