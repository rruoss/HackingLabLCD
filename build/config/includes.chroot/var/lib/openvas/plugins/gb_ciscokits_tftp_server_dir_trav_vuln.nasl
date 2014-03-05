###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ciscokits_tftp_server_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CiscoKits TFTP Server Directory Traversal Vulnerability
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
tag_affected = "CiscoKits TFTP Server Version 1.0 and prior.";
tag_insight = "The flaw is due to an error while handling certain requests containing
  'dot dot' sequences (..), which can be exploited to download arbitrary files
  from the host system.";
tag_solution = "No solution or patch is available as of 08th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.certificationkits.com/";
tag_summary = "The host is running CiscoKits TFTP Server and is prone to
  directory traversal vulnerability.";

if(description)
{
  script_id(801965);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_bugtraq_id(49053);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("CiscoKits TFTP Server Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=301");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17619/");
  script_xref(name : "URL" , value : "http://secpod.org/SECPOD_CiscoKits_TFTP_Server_Dir_Trav_POC.py");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_CiscoKits_TFTP_Server_Dir_Trav.txt");

  script_description(desc);
  script_summary("Check for the directory traversal attack on CiscoKits TFTP Server");
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

## Check for tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

foreach file (make_list("windows/win.ini", "winnt/win.ini"))
{
  ## Try The Exploit
  response = tftp_get(port:port, path:"../../../../../../../../../" +
                                      "../../../" + file);
  ## Check The Response
  if("; for 16-bit app support" >< response)
  {
    security_warning(port:port);
    exit(0);
  }
}
