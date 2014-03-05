###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Test Webserver SSL Certificate
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
#
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
tag_summary = "This plugin uses openssl to verify TLS/SSL Certificates.";

if(description)
{
  script_id(96057);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Test Webserver SSL Certificate");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Test Webserver SSL Certificate");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_add_preference(name:"X.509 Root Authority Certificate(PEM)", type:"file", value:"");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


if (get_kb_item("Ports/tcp/443")) port = 443;
else {
  set_kb_item(name: "GSHB/SSL-Cert", value: "none");
  exit(0);
}
RootPEM = script_get_preference_file_content("X.509 Root Authority Certificate(PEM)");

temp = get_tmp_dir();
ip = get_host_ip();

fwrite(file:temp + ip + "-GSHB_RootPEM.pem",data:RootPEM);

p = 0;
argv[p++] = "openssl";
argv[p++] = "verify";
argv[p++] = temp + ip + "-GSHB_RootPEM.pem";

RootPEMstate = pread(cmd: "openssl", argv: argv, cd: 5);

if (RootPEMstate =~ ".*-GSHB_RootPEM.pem: OK.*")
{
  i = 0;
  argv[i++] = "openssl";
  argv[i++] = "s_client";
  argv[i++] = "-CAfile";
  argv[i++] = temp + ip + "-GSHB_RootPEM.pem";  
  argv[i++] = "-connect"; 
  argv[i++] = ip + ":" + port;

  sslcert = pread(cmd: "openssl", argv: argv, cd: 5);
  RootPEMstate = "OK";
}else{
  i = 0;
  argv[i++] = "openssl";
  argv[i++] = "s_client";
  argv[i++] = "-connect"; 
  argv[i++] = ip + ":" + port;

  sslcert = pread(cmd: "openssl", argv: argv, cd: 5);
  RootPEMstate = "FAIL";
}
if("unknown protocol" >!< sslcert){
  subject = egrep (string:sslcert, pattern:"subject=.*");
  rtcode = egrep (string:sslcert, pattern:"Verify return code:.*");
  certresult = subject + rtcode;
}else{
  certresult = "unknown";
  log_message(port:0, proto: "IT-Grundschutz", data:sslcert);
}
unlink(temp + ip + "-GSHB_RootPEM.pem");

set_kb_item(name: "GSHB/SSL-Cert", value: certresult);
set_kb_item(name: "GSHB/SSL-Cert/RootPEMstate", value: RootPEMstate);
exit (0);
