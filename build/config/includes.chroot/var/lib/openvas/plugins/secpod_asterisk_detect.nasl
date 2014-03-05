###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_asterisk_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Asterisk Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# Updated to Set KB for Product Installation
#  - By Sharath S <sharaths@secpod.com> On 2009-08-28
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
tag_summary = "Detection of Asterisk
                     
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900811";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Asterisk Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Identify the version of Asterisk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl");
  script_require_keys("Services/udp/sip");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

function get_sip_banner(asterisk_port)
{
  local_var soc, r, opt, asterisk_banner;
  global_var asterisk_port;

  if (islocalhost())
    soc = open_sock_udp(asterisk_port);
  else
    soc = open_priv_sock_udp(sport:5060, dport:asterisk_port);
  if(!soc)
    return NULL;

  sndReq = string(
            "OPTIONS sip:user@", get_host_name(), " SIP/2.0", "\r\n",
            "Via: SIP/2.0/UDP ", this_host(), ":", asterisk_port, "\r\n",
            "To: User <sip:user", get_host_name(), ":", asterisk_port, ">\r\n",
            "From: OpenVAS <sip:openvas@", this_host(), ":", asterisk_port, ">\r\n",
            "Call-ID: ", rand(), "\r\n",
            "CSeq: ", rand(), " OPTIONS\r\n",
            "Contact: OpenVAS <sip:openvas@", this_host(), ">\r\n",
            "Max-Forwards: 10\r\n",
            "Accept: application/sdp\r\n",
            "Content-Length: 0\r\n\r\n");

  send(socket:soc, data:sndReq);
  rcvRes = recv(socket:soc, length:1024);

  if("SIP/2.0" >< rcvRes && ("Server:" >< rcvRes))
  {
    asterisk_banner = egrep(pattern:'^Server:', string:rcvRes);
    asterisk_banner = substr(asterisk_banner, 8);
  }

  else if("SIP/2.0" >< rcvRes && ("User-Agent" >< rcvRes))
  {
    asterisk_banner = egrep(pattern:'^User-Agent', string:rcvRes);
    asterisk_banner = substr(asterisk_banner, 12);
  }

  if(!isnull(asterisk_banner))
    return asterisk_banner;
  return NULL;
}

asterisk_port = get_kb_item("Services/udp/sip");
if(!asterisk_port)
  asterisk_port = 5060;

if(get_udp_port_state(asterisk_port))
{
  asterisk_banner = get_sip_banner(port:asterisk_port);

  if("Asterisk PBX" >< asterisk_banner)
  {
    asteriskVer = eregmatch(pattern:"Asterisk PBX ([0-9.]+(.?[a-z0-9]+)?)",
                            string:asterisk_banner);
    asteriskVer[1] = ereg_replace(pattern:"-", replace:".", string:asteriskVer[1]);

    if(asteriskVer[1] != NULL){
      set_kb_item(name:"Asterisk-PBX/Ver", value:asteriskVer[1]);
      set_kb_item(name:"Asterisk-PBX/Installed", value:TRUE);
    
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:asteriskVer[1], exp:"^([0-9.]+\.[0-9])\.?(rc[0-9]+)?", base:"cpe:/a:digium:asterisk:");
      if(isnull(cpe))
        cpe = 'cpe:/a:digium:asterisk';

      register_product(cpe:cpe, location: asterisk_port + '/udp', nvt:SCRIPT_OID, port:asterisk_port);
      log_message(data: build_detection_report(app:"Asterisk-PBX", version:asteriskVer[1], install:asterisk_port + '/udp', cpe:cpe, concluded: asterisk_banner),
                                               port:port);

    }
    else
      set_kb_item(name:"Asterisk-PBX/Installed", value:TRUE);
  }
}
