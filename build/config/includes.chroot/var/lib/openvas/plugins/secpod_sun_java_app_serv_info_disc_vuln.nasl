###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_java_app_serv_info_disc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun Java System Application Server Information Disclosure vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_solution = "Apply the security updates.
  http://sunsolve.sun.com/search/document.do?assetkey=1-66-245446-1

  *****
  NOTE: Please ignore this warning, if above mentioned patch is applied.
  *****";

tag_impact = "Successful exploitation could allow remote unprivileged user to read Web
  Application configuration files in 'WEB-INF' and 'META-INF' directories.
  Impact Level: Application";
tag_affected = "Java System Application Server version 8.1 and 8.2 on Linux and Windows.";
tag_insight = "A security vulnerability in Java Application server may expose sensitive
  directory contents i.e. 'WEB-INF' and 'META-INF' via malformed requests.";
tag_summary = "The host is running Java Application Server and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_id(900301);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-06 06:53:35 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0278");
  script_bugtraq_id(33397);
  script_name("Sun Java System Application Server Information Disclosure vulnerability");
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

  script_xref(name : "URL" , value : "http://osvdb.org/51604");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33725");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48161");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-119166-35-1");

  script_description(desc);
  script_summary("Check for the version of Java Application Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_sun_java_app_serv_detect.nasl");
  script_require_keys("Sun/Java/AppServer/Ver");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");

port = get_http_port(default:8080);
if(!port){
  exit(0);
}

appservVer = get_kb_item("Sun/Java/AppServer/Ver");
if(appservVer)
{
  # Check for Java Application Server version 8.1 and 8.2
  if(appservVer =~ "(8\.1|8\.2)"){
    security_warning(port);
  }
}
