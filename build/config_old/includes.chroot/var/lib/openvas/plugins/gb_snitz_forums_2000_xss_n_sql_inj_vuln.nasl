###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snitz_forums_2000_xss_n_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Snitz Forums 2000 'members.asp' SQL Injection and Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_solution = "Apply the patch from below link,
  http://forum.snitz.com/forum/topic.asp?TOPIC_ID=69770

  *****
  NOTE : Ignore this warning, if above mentioned patch is applied already.
  *****";

tag_impact = "Successful exploitation could allow an attacker to steal cookie-based
  authentication credentials, compromise the application, access or modify
  data, or exploit latent vulnerabilities in the underlying database.
  Impact Level: Application";
tag_affected = "Snitz Forums 2000 version 3.4.07";
tag_insight = "- Input passed to the 'M_NAME' parameter in members.asp is not properly
    sanitised before being returned to the user. This can be exploited to
    execute arbitrary HTML and script code in a user's browser session in
    context of an affected site.
  - Input passed to the 'M_NAME' parameter in members.asp is not properly
    sanitised before being used in SQL queries. This can be exploited to
    manipulate SQL queries by injecting arbitrary SQL code.";
tag_summary = "The host is running Snitz and is prone to SQL injection and cross
  site scripting vulnerabilities.";

if(description)
{
  script_id(802243);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_bugtraq_id(45381);
  script_cve_id("CVE-2010-4826", "CVE-2010-4827");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Snitz Forums 2000 'members.asp' SQL Injection and Cross Site Scripting Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://osvdb.org/69794");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42308");
  script_xref(name : "URL" , value : "http://forum.snitz.com/forum/topic.asp?TOPIC_ID=69770");

  script_description(desc);
  script_summary("Check for the version of Snitz Forums");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("snitz_forums_2000_detect.nasl");
  script_require_ports("Services/www", 80);
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
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get version from KB
ver =  get_version_from_kb(port:port, app:"SnitzForums");
if(ver)
{
  ## Check Snitz Forums 2000 version 3.4.07
  if(version_is_equal(version:ver, test_version:"3.4.07")){
    security_hole(port);
  }
}
