##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mahara_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Mahara Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By : Sooraj KS <kssooraj@secpod.com> on 2011-03-30
# Added /ChangeLog to detect recent version.
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
################################################################################

include("revisions-lib.inc");
tag_summary = "This script detects the installed version of Mahara and
  sets the result in KB.";

if(description)
{
  script_id(900381);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Mahara Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the Version of Mahara");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900381";
SCRIPT_DESC = "Mahara Version Detection";

maharaPort = get_http_port(default:80);
if(!maharaPort){
  maharaPort = 80;
}

if(!get_port_state(maharaPort)){
  exit(0);
}

foreach dir (make_list("/mahara" , "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/htdocs/index.php"), port:maharaPort);
  rcvRes = http_send_recv(port:maharaPort, data:sndReq);
  if("Welcome to Mahara" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/htdocs/admin/index.php"),
                      port:maharaPort);
    rcvRes = http_send_recv(port:maharaPort, data:sndReq);
  }

  # Check for Welcome page and Login Page with proper Response
  if(("Log in to Mahara" >< rcvRes || "Welcome to Mahara" >< rcvRes)
     && egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    foreach path (make_list("/Changelog", "/ChangeLog", "/debian/Changelog"))
    {
      # sndReq2 = string("GET ", dir, path, " \r\n\r\n");
      sndReq2 = string("GET ", dir, path, " \r\n\r\n");
      rcvRes2 = http_send_recv(port:maharaPort, data:sndReq2);
      if("mahara" >< rcvRes2)
      {
        # For greping the version line
        ver = egrep(pattern:"([0-9]\.[0-9]\.[0-9]+)", string:rcvRes2);
        # For matching the version
        ver = eregmatch(pattern:"^(mahara\ )?\(?(([0-9]\.[0-9]\.[0-9]+)(\~" +
                                "(beta|alpha)([0-9]))?\-?([0-9])?)\)?([^0-9]"+
                                "|$)", string:ver);
        # For replacing '~' or '-' with '.'
          maharaVer = ereg_replace(pattern:string("[~|-]"), replace:string("."),
                    string:ver[2]);
      }

      if(maharaVer != NULL)
      {
        tmp_version = maharaVer + " under " + dir;
        set_kb_item(name:"www/"+ maharaPort + "/Mahara",
                    value:tmp_version);
        security_note(data:"Mahara version " + maharaVer + " running at location " +
		                    dir +  " was detected on the host", port:maharaPort);
   
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:mahara:mahara:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

        break;
      }
    }
  }
}
