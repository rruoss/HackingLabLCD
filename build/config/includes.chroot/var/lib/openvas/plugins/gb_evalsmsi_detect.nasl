###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_evalsmsi_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# evalSMSI Version Detection
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_summary = "This script finds the installed evalSMSI version and saves
  the result in KB.";

if(description)
{
  script_id(800165);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("evalSMSI Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of evalSMSI in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800165";
SCRIPT_DESC = "evalSMSI Version Detection";

## Get the port where evalSMSI application is running
evalSMSIPort = get_http_port(default:80);
if(!evalSMSIPort){
  exit(0);
}

## Iterate over the list of application paths
foreach path (make_list("/evalsmsi", "/", cgi_dirs()))
{
  ## Send the request and Recieve the response
  sndReq = http_get(item: path + "/evalsmsi.php", port:evalSMSIPort);
  rcvRes = http_send_recv(port:evalSMSIPort, data:sndReq);

  ## Check for EvalSMSI Application in the response
  if(">EvalSMSI" >< rcvRes)
  {
    ## Get EvalSMSI version
    evalSMSIVer = eregmatch(pattern:">EvalSMSI version ([0-9.]+) ?--",
                            string:rcvRes);
    if(evalSMSIVer[1] != NULL)
    {
      tmp_version = evalSMSIVer[1] + " under " + path;
      set_kb_item(name:"www/" + evalSMSIPort + "/evalSMSI",
                        value:tmp_version);
      security_note(data:"Eval SMSI version " + evalSMSIVer[1] + " running at" + 
                         " location " + path + " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:myshell:evalsmsi:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}
