###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openfiler_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Openfiler Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML
  and script code, arbitrary commands in a user's browser session in context
  of an affected site and gain sensitive information.
  Impact Level: Application";
tag_affected = "Openfiler versions 2.3, 2.99.1, 2.99.2";
tag_insight = "- 'usercookie' and 'passcookie' cookies contain the username and password,
    respectively, in plain text and these cookies are not protected with the
    'HttpOnly' flag.
  - Input passed to the 'device' parameter in system.html and 'targetName'
    parameter in volumes_iscsi_targets.html is not properly sanitised before
    being returned to the user.
  - Access not being restricted to uptime.html and phpinfo.html can be
    exploited to disclose PHP configuration details.
  - Input passed to the 'device' parameter in
    /opt/openfiler/var/www/htdocs/admin/system.html is not properly
    satinitised, which allows 'openfiler' user to execute arbitrary commands
    by injecting commands into the 'device' parameter.";
tag_solution = "No solution or patch is available as of 25th September, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.openfiler.com/";
tag_summary = "This host is running Openfiler and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802967);
  script_version("$Revision: 12 $");
  script_bugtraq_id(55500);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-25 17:31:13 +0530 (Tue, 25 Sep 2012)");
  script_name("Openfiler Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42507");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/21191/");
  script_xref(name : "URL" , value : "http://forums.cnet.com/7726-6132_102-5357559.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/116405/openfiler_networkcard_exec.rb.txt");
  script_xref(name : "URL" , value : "http://itsecuritysolutions.org/2012-09-06-Openfiler-v2.x-multiple-vulnerabilities/");
  script_xref(name : "URL" , value : "https://dev.openfiler.com/attachments/152/Openfiler_v2.99.1_multiple_vulnerabilities.txt");

  script_description(desc);
  script_summary("Check if Openfiler is vulnerable to information disclosure vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 446);
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
include("openvas-https.inc");

## Variable Initialization
port = "";
req = "";
res = "";
host = "";
url = "";
req2 = "";
res2 = "";

## HTTP Port
port = "446";

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Get host
host = get_host_name();
if(! host){
  exit(0);
}

## Construct request
req = string("GET / HTTP/1.1\r\n",
             "Host: ", host, ":", port, "\r\n\r\n");

## Confirm the application before trying exploit
res = https_req_get(port:port, request:req);
if(res && ">Openfiler Storage Control Center<" >< res && ">Openfiler<" >< res)
{
  ## Construct attack request
  url = '/phpinfo.html';
  req2 = string("GET ", url, " HTTP/1.1\r\n",
                "Host: ", host, ":", port, "\r\n",
                "User-Agent: Openfiler Information Disclosure\r\n\r\n");

  res2 = https_req_get(port:port, request:req2);

  ## Check the response to confirm vulnerability
  if(res2 && ">phpinfo()<" >< res2 && ">System" >< res2 && ">PHP API" >< res2){
    security_warning(port);
  }
}
