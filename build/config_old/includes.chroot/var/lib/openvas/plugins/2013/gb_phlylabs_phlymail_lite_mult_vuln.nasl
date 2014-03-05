###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phlylabs_phlymail_lite_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# phlyLabs phlyMail Lite Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site
  and displaying the full webapp installation path.
  Impact Level: Application";

tag_affected = "phlyLabs phlyMail Lite version 4.03.04";
tag_insight = "- Input passed via the 'go' parameter in 'derefer.php' script is not
    properly verified before being used to redirect users. This can be
    exploited to redirect a user to an arbitrary website.
  - phlyMail suffers from multiple stored XSS vulnerabilities (post-auth)
    and path disclosure when input passed via several parameters to several
    scripts is not properly sanitized before being returned to the user.";
tag_solution = "No solution or patch is available as of 15th January, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://phlymail.com/en/index.html";
tag_summary = "This host is installed with phlyLabs phlyMail Lite and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(803151);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57303, 57304);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-15 12:12:35 +0530 (Tue, 15 Jan 2013)");
  script_name("phlyLabs phlyMail Lite Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24087");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24086");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013010113");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5122.php");

  script_description(desc);
  script_summary("Check if phlyMail Lite is vulnerable to open redirect");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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

port = "";
req = "";
res = "";
dir = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
 port = 80;
}

## Check the port status
if(!get_port_state(port)){
 exit(0);
}

## Check the php support
if(!can_host_php(port:port)){
  exit(0);
}

## iterate over the possible paths
foreach dir (make_list("", "/phlymail/phlymail", cgi_dirs()))
{
  ## Application Confirmation
  if(http_vuln_check(port:port, url:dir + "/index.php",
     pattern:">phlyMail Lite<", check_header:TRUE,
     extra_check:make_list('>Passwort vergessen?', '>Passwort:<')))
  {

    ## Construct attack request
    req = http_get(item:string(dir,"/frontend/derefer.php?go=",
    "http://",get_host_ip(),dir,"/index.php"), port:port);

    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if(res =~ "HTTP/1.. 302" && res =~ "Location:.*index.php")
    {
      security_hole(port);
      exit(0);
    }
  }
}
