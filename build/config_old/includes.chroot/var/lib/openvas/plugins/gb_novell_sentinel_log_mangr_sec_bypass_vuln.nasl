###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_sentinel_log_mangr_sec_bypass_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Novell Sentinel Log Manager Retention Policy Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to bypass certain security
  restrictions.
  Impact Level: Application";
tag_affected = "Novell Sentinel Log Manager version 1.2.0.2 and prior";
tag_insight = "The flaw is due to an error when saving a retention policy and can be
  exploited by a report administrator (read only role) to create new
  policies.";
tag_solution = "Apply the patch or upgrade to 1.2.0.3 or later,
  https://www.netiq.com/products/sentinel-log-manager/";
tag_summary = "The host is running Novell Sentinel Log Manager and is prone security bypass
  vulnerability.";

if(description)
{
  script_id(803110);
  script_version("$Revision: 12 $");
  script_bugtraq_id(55767);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-23 15:27:29 +0530 (Fri, 23 Nov 2012)");
  script_name("Novell Sentinel Log Manager Retention Policy Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/85955");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50797/");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2012-10/0026.html");
  script_xref(name : "URL" , value : "https://www.netiq.com/documentation/novelllogmanager12/log_manager_readme/data/log_manager_readme.html");

  script_description(desc);
  script_summary("Check Novell Sentinel Log Manager is vulnerable to security bypass");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8443);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("openvas-https.inc");

port = 0;
req1 = "";
res1 = "";
req2 = "";
res2 = "";

## Default HTTPS port
port = get_http_port(default:8443);
if(!port){
  port = 8443;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Initial request
req1 = http_get(item:"/novelllogmanager/views/logon.html", port:port);
res1 = https_req_get(port:port, request:req1);

## Confirm the application before trying the exploit
if(res1 && ">Novell Sentinel Log Manager" >< res1 &&
   ">Novell Identity Audit<" >< res1)
{
  ## Post data
  post_data = '5|0|9|https://' + host + ':' + port + '/novelllogmanager/' +
              'com.novell.siem.logmanager.LogManager/|E377321CAAD2FABED6' +
              '283BD3643E4289|com.novell.sentinel.scout.client.about.Abo' +
              'utLogManagerService|getLogManagerInfo|1|2|3|4|0|';

  ## Construct the POST request
  req2 = string("POST /novelllogmanager/datastorageservice.rpc HTTP/1.1\r\n",
                "Host: ", host, port, "\r\n",
                "DNT: n",
                "Content-Type: text/x-gwt-rpc; charset=utf-8\r\n",
                "Content-Length: ", strlen(post_data), "\r\n",
                "\r\n", post_data);

  ## Receive the response
  res2 = https_req_get(port:port, request:req2);

  ## Check Attack pattern in the response
  if("The call" >< res2 && "on the server;" >< res2 &&
     "server log for details" >< res2){
    security_hole(port);
  }
}
