##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cutenews_detect_win_900128.nasl 42 2013-11-04 19:41:32Z jan $
# Description: CuteNews Version Detection for Windows
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_summary = "This script find the CuteNews installed version of Windows and
 saves the version in KB.";

if(description)
{
 script_id(900128);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_name("CuteNews Version Detection for Windows");
 script_summary("Set File Version of CuteNews in KB");
 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


 include("http_func.inc");
 include("http_keepalive.inc");
 include("cpe.inc");
 include("host_details.inc");

 ## Constant values
 SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900128";
 SCRIPT_DESC = "CuteNews Version Detection for Windows";

 port = get_http_port(default:80);
 if(!port){
        exit(0);
 }

 foreach dir (make_list("/cutenews", cgi_dirs()))
 {
        sndReq = http_get(item:string(dir, "/index.php"), port:port);
        rcvRes = http_keepalive_send_recv(port:port, data:sndReq);
        if(rcvRes == NULL){
                exit(0);
        }

        if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
        {
                cutenewsVer = egrep(pattern:"CuteNews v[0-9.]+", string:rcvRes);
                cutenewsVer = eregmatch(pattern:"[0-9.]+", string:cutenewsVer);
                if(cutenewsVer != NULL){

                        tmp_version = cutenewsVer[0] + " under " + dir;
                        set_kb_item(name:"www/"+ port + "/CuteNews",
                                      value:tmp_version);
                        security_note(data:"CuteNews version " + cutenewsVer[0]
                                           + " running at location " + dir +
                                                 " was detected on the host");
   
                        ## build cpe and store it as host_detail
                        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:cutephp:cutenews:");
                        if(!isnull(cpe))
                           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

                }
        }
 }
