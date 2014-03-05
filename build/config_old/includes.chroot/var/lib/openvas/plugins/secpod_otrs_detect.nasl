###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_otrs_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Open Ticket Request System (OTRS) Version Detection
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902018";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version ("$Revision: 44 $");
  script_tag(name:"detection", value:"remote probe");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_name("Open Ticket Request System (OTRS) and ITSM Version Detection");

tag_summary =
"The script sends a connection request to the server and attempts to extract
the version number from the reply.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Checks for the presence of Open Ticket Request System (OTRS) and ITSM");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Function to Register Product and Build report
function build_report(app, ver, cpe, insloc, port)
{
  register_product(cpe:cpe, location:insloc, nvt:SCRIPT_OID, port:port);

  log_message(data: build_detection_report(app:app,
                                           version:ver,
                                           install:insloc,
                                           cpe:cpe,
                                           concluded:ver),
                                           port:port);
}

otrsPort = get_http_port(default:80);
if(!otrsPort){
  otrsPort = 80;
}

if(!get_port_state(otrsPort)){
  exit(0);
}

foreach dir (make_list("", "/support", "/OTRS", "/otrs", cgi_dirs()))
{
  foreach path (make_list("/public.pl", "/index.pl", "/installer.pl"))
  {
    sndReq = http_get(item:string(dir , path), port:otrsPort);
    rcvRes = http_send_recv(port:otrsPort, data:sndReq, bodyonly:1);

    if(rcvRes && (egrep(pattern:"Powered by OTRS|Powered by.*OTRS", string:rcvRes)))
    {
      if( strlen( dir ) > 0 )
        install = dir;
      else
        install = '/';

      otrsVer = eregmatch(pattern:"Powered by.*OTRS ([0-9\.\w]+)" , string:rcvRes);
      if(otrsVer[1] != NULL)
      {
        set_kb_item(name:"www/" + otrsPort + "/OTRS", value:otrsVer[1] + ' under ' + install);
        set_kb_item(name:"OTRS/installed",value:TRUE);

        cpe = build_cpe(value:otrsVer[1], exp:"^([0-9.]+)", base:"cpe:/a:otrs:otrs:");
        if(isnull(cpe))
           cpe = 'cpe:/a:otrs:otrs';

        ## Register OTRS Product and Build Report
        build_report(app:"OTRS", ver:otrsVer[1], cpe:cpe, insloc:install, port:otrsPort);

        ## To detect OTRS::ITSM

        sndReq = http_get(item:string(dir , "/index.pl"), port:otrsPort);
        rcvRes = http_send_recv(port:otrsPort, data:sndReq, bodyonly:1);

        if(rcvRes && "Welcome to OTRS::ITSM" >< rcvRes)
        {
          itsmver = eregmatch(pattern:"Welcome to OTRS::ITSM ([0-9\.\w]+)" , string:rcvRes);

          if(itsmver[1] != NULL)
          {
            set_kb_item(name:"www/" + otrsPort + "/OTRS ITSM", value:itsmver[1] + ' under ' + install);
            set_kb_item(name:"OTRS ITSM/installed",value:TRUE);

            cpe = build_cpe(value:itsmver[1], exp:"^([0-9.]+)", base:"cpe:/a:otrs:otrs_itsm:");
            if(isnull(cpe))
              cpe = 'cpe:/a:otrs:otrs_itsm';

            ## Register ITSM Product and Build Report
            build_report(app:"OTRS ITSM", ver:itsmver[1], cpe:cpe, insloc:install, port:otrsPort);
          }
        }
        break;
      }
    }
  }
}

