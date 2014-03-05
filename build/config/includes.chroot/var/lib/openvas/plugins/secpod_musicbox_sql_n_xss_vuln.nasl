###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_musicbox_sql_n_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Musicbox SQL Injection and Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow the attackers to view, add, modify or
  delete information in the back-end database and to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "Musicbox Version 3.7 and prior.";
tag_insight = "The flaws are due to input passed to the 'action' and 'in' parameter
  in 'index.php' is not properly sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 26th July, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.musicboxv2.com/";
tag_summary = "The host is running Musicbox and is prone to SQL injection and
  cross site scripting vulnerabilities.";

if(description)
{
  script_id(902461);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Musicbox SQL Injection and Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17570/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103369/musicbox-sqlxss.txt");

  script_description(desc);
  script_copyright("Copyright (c) 2011 SecPod");
  script_summary("Confirm the vulnerability in Musicbox");
  script_category(ACT_ATTACK);
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

## Get HTTP Port
phpPort = get_http_port(default:80);
if(!phpPort){
  exit(0);
}

if(!can_host_php(port:phpPort)){
  exit(0);
}

foreach dir (make_list("/musicbox", "/", cgi_dirs()))
{
  ## Send and Receive request
  sndReq = http_get(item:string(dir, "/index.php"), port:phpPort);
  rcvRes = http_send_recv(port:phpPort, data:sndReq);

  ## Confirm application
  if("<title>Musicbox" >< rcvRes)
  {
    ## Construct the attack
    sndReq = http_get(item:string(dir, '/index.php?in=song&term="><script>' +
                      'alert(document.cookie)<%2Fscript>&action=search&st' +
                      'art=0'), port:phpPort);
    rcvRes = http_send_recv(port:phpPort, data:sndReq);

    ## Confirm the exploit
    if('"><script>alert(document.cookie)</script>"' >< rcvRes)
    {
      security_hole(phpPort);
      exit(0);
    }
  }
}
