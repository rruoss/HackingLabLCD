###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts2_mult_redirect_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Apache Struts2 Redirection and Security Bypass Vulnerabilities
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
  script_id(803838);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-2248", "CVE-2013-2251");
  script_bugtraq_id(61196, 61189);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-24 11:58:54 +0530 (Wed, 24 Jul 2013)");
  script_name("Apache Struts2 Redirection and Security Bypass Vulnerabilities");

  tag_summary =
"This host is running Apache Struts2 and is prone to redirection and security
bypass vulnerabilities.";

  tag_vuldetect =
"Send an expression along with the redirect command via HTTP GET request and
check whether it is redirecting and solve the expression or not.";

  tag_insight =
"Flaws are due to improper sanitation of 'action:', 'redirect:', and
'redirectAction:' prefixing parameters before being used in
DefaultActionMapper.";

  tag_impact =
"Successful exploitation will allow remote attacker to execute arbitrary
arbitrary Java code via OGNL (Object-Graph Navigation Language) or redirect
user to a malicious url.";

  tag_affected =
"Apache Struts 2.0.0 to 2.3.15";

  tag_solution =
"Upgrade to Apache Struts 2 version 2.3.15.1 or later,
For updates refer to http://struts.apache.org";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/95405");
  script_xref(name : "URL" , value : "http://www.osvdb.com/95406");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54118");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Jul/157");
  script_xref(name : "URL" , value : "http://struts.apache.org/development/2.x/docs/s2-016.html");
  script_xref(name : "URL" , value : "http://struts.apache.org/development/2.x/docs/s2-017.html");
  script_xref(name : "URL" , value : "http://struts.apache.org/release/2.3.x/docs/version-notes-23151.html");
  script_summary("Check if Apache Struts2 is vulnerable to arbitrary redirection vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
asport = 0;
asreq = "";
asres = "";
res = "";
req = "";
result = "";
dir = "";
url = "";

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
foreach dir (make_list("", "/struts2", "/struts", "/framework", "/struts2-showcase"))
{
  ## Send and Receive the response
  asreq = http_get(item:string(dir,"/showcase.action"), port:asport);
  asres = http_keepalive_send_recv(port:asport, data:asreq);

  ## Confirm the application
  if(asres && ">Struts2 Showcase<" >< asres && ">Welcome!<" >< asres)
  {
    calc = make_list(2, 3);

    foreach i (calc)
    {
      ## Construct attack request
      url = dir + "/showcase.action?redirect%3A%25%7B"+ i +"*5%7D";

      req = http_get(item:url, port:asport);
      res = http_keepalive_send_recv(port:asport, data:req);

      if(res =~ "HTTP/1.. 302" && res =~ "Location:.*/([0-9]+)?")
      {
        result = eregmatch(pattern: string(dir, "/([0-9]+)?"), string:res);

        if ( !result || result[1] >!< i * 5 ) exit(0);
      }
      else exit(0);
    }
    security_hole(port);
    exit(0);
  }
}
