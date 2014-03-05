##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_xwork_info_disc_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Apache Struts2 'XWork' Information Disclosure Vulnerability
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
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to obtain potentially sensitive
  information about internal Java class paths via vectors involving an s:submit
  element and a nonexistent method,
  Impact Level: Application.";
tag_affected = "XWork version 2.2.1 in Apache Struts 2.2.1";

tag_insight = "The flaw is due to error in XWork, when handling the 's:submit'
  element and a nonexistent method, which gives sensitive information about
  internal Java class paths.";
tag_solution = "Upgrade to Struts version 2.2.3 or later
  For updates refer to http://struts.apache.org/download.cgi";
tag_summary = "This host is running Apache Struts and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_id(801940);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_cve_id("CVE-2011-2088");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Apache Struts2 'XWork' Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "https://issues.apache.org/jira/browse/WW-3579");
  script_xref(name : "URL" , value : "http://www.ventuneac.net/security-advisories/MVSA-11-006");

  script_description(desc);
  script_summary("Check if Apache Struts is vulnerable to information disclosure vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
 port = 8080 ;
}

if(!get_port_state(port)){
  exit(0);
}

## check the possible paths
foreach dir (make_list("/", "/struts", "/struts2-blank"))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/example/HelloWorld.action"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if("<title>Struts" >< res)
  {
    ## Construct the request to get no existing methods
    req = http_get(item:string(dir,"/Nonmethod.action"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    ##  Confirm the exploit
    if("Stacktraces" >< res &&  "Nonmethod" >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
