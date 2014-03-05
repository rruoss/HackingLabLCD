###############################################################################
# OpenVAS Vulnerability Test
# $Id: JBoss_enterprise_aplication_server_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# JBoss Enterprise Application Server Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100387";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-12-10 14:34:38 +0100 (Thu, 10 Dec 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"detection", value:"remote probe");

 tag_summary =
"The script sends a connection request to the server and attempts to
extract the version number from the reply.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

 script_xref(name : "URL" , value : "http://www.jboss.com/products/platforms/application/");
 script_name("JBoss Enterprise Application Server Detection");
 script_description(desc);
 script_summary("Checks for the presence of JBoss Enterprise Application Server");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}


include("http_func.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");


port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if(egrep(pattern:"X-Powered-By.*JBoss(AS|EAS)?-", string:banner))
 {
   vers = 'unknown';
   version = eregmatch(pattern:"JBoss(AS|EAS)?-([0-9.]+[RC]*[GA_CP0-9]*)", string: banner);
   if(!isnull(version[2]))vers = version[2];

     set_kb_item(name: string("www/", port, "/jboss_enterprise_application_server"), value: version[2]);
     set_kb_item(name:"jboss_enterprise_application_server/installed", value:TRUE);

     cpe = build_cpe(value:version[2], exp:"(^[0-9.]+)", base:"cpe:/a:redhat:jboss_enterprise_application_platform:");
     if(isnull(cpe))
       cpe = "cpe:/a:redhat:jboss_enterprise_application_platform";
     else
       if(version[2] =~ 'RC[0-9]+|CP[0-9]+') {
         cpe = ereg_replace(pattern:"(\.$)", string:cpe, replace:'');
         cpe_match = eregmatch(pattern:"(RC[0-9]+|CP[0-9]+)", string:version[2]);
         if(!isnull(cpe_match[1]))cpe = cpe + ':' + tolower(cpe_match[1]);
       }  

     register_product(cpe:cpe, location:port + '/tcp', nvt:SCRIPT_OID, port:port);

     log_message(data: build_detection_report(app:"JBoss Enterprise Application Server",version:vers,install:port + '/tcp',cpe:cpe,concluded: version[0]),
                 port:port);

     exit(0);
   
 }

exit(0);

