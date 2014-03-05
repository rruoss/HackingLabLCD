##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_noticeboard_pro_sql_n_file_upload_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# NoticeBoardPro SQL Injection and Arbitrary File Upload Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  script code in a user's browser session in the context of an affected
  application and to manipulate SQL queries by injecting arbitrary SQL code.
  Impact Level: Application.";
tag_affected = "NoticeBoardPro version 1.0";

tag_insight = "The flaws are due to
  - Input passed via the 'userID' parameter to 'deleteItem3.php' is not
    properly sanitised before being used in SQL queries.
  - An error in 'editItem1.php' script, while validating an uploaded files
    which leads to execution of arbitrary PHP code by uploading a PHP file.";
tag_solution = "No solution or patch is available as of 5th July 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.NoticeBoardPro.com/";
tag_summary = "This host is running NoticeBoardPro and is prone to SQL injection
  and arbitrary file upload vulnerabilities.";

if(description)
{
  script_id(802114);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("NoticeBoardPro SQL Injection and Arbitrary File Upload Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44595/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17296/");

  script_description(desc);
  script_summary("Check for the version of NoticeBoardPro");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
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

## Get the default port
nbPort = get_http_port(default:80);
if(!nbPort){
  nbPort = 80;
}

## check the port state
if(!get_port_state(nbPort)){
  exit(0);
}

foreach dir (make_list("/NoticeBoardPro", "/noticeboardpro", "/", cgi_dirs()))
{
  ## Send and recieve the data
  sndReq = http_get(item: string(dir, "/index.php"), port:nbPort);
  rcvRes = http_keepalive_send_recv(port:nbPort, data:sndReq);

  ## Confirm the application
  if("<title>Notice Board</title>" >< rcvRes)
  {
    nbVer = eregmatch(pattern:">Version ([0-9.]+)" , string:rcvRes);
    if(nbVer[1] != NULL)
    {
      if(version_is_equal(version:nbVer[1], test_version:"1.0")){
       security_hole(nbPort);
      }
    }
  }
}
