###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-020_remote.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft SMB Transaction Parsing Remote Code Execution Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code on the system.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 SP1 and prior
  Microsoft Windows 2008 SP2 and prior
  Microsoft Windows Vista SP2 and prior
  Microsoft Windows 2008 R2 SP1 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2003 Service Pack 2 and prior";
tag_insight = "The flaw is due to improper validation of field in SMB request,
  which allows remote attackers to execute arbitrary code on the system by
  sending a malformed SMB request.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS11-020";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-020.";

if(description)
{
  script_id(902660);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-0661");
  script_bugtraq_id(47198);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-06 11:57:33 +0530 (Tue, 06 Mar 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft SMB Transaction Parsing Remote Code Execution Vulnerability");
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
  script_summary("Determine if SMB server is prone to remote code execution vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_smb_accessible_shares.nasl", "smb_login.nasl");
  script_require_keys("SMB/Accessible_Shares", "SMB/login", "SMB/password");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/71781");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44072/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1025329");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/cas/techalerts/TA11-102A.html");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-020");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

## Variable Initialization

name     = "";
domain   = "";
port     = 0;
soc1     = "";
r        = "";
tid      = "";
uid      = "";
fid      = "";
tid_high = "";
tid_low  = "";
uid_high = "";
uid_low  = "";
fid_high = "";
fid_low  = "";
prot     = "";
shares   = "";
share    = "";
file     = "";
resp     = "";
read_resp = "";
dir = NULL;
smb_read_andx_req = "";

## Get name, domain and port
name   = kb_smb_name();
domain = kb_smb_domain();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();

## Open the socket
soc1 = open_sock_tcp(port);
if(!soc1){
  exit(0);
}

if(!login)login = "anonymous";
if(!pass) pass = "";

## Get accessible shares
shares = get_kb_list("SMB/Accessible_Shares");
if (isnull(shares))
{
  close(soc1);
  exit(0);
}

## Send SMB Negotiate Protocol Req
prot = smb_neg_prot(soc:soc1);
if(!prot){
  close(soc1);
  exit(0);
}

## Send SMB Session Setup and Andx Req
r = smb_session_setup(soc:soc1, login:login, password:"", domain:domain, prot:prot);
if(!r)
{
  close(soc1);
  exit(0);
}

## Get the User_ID
uid = session_extract_uid(reply:r);
if(!uid)
{
  close(soc1);
  exit(0);
}

foreach share (shares)
{
  ## Send SMB Tree Connect Andx Req
  r = smb_tconx(soc:soc1, name:name, uid:uid, share:share);

  if(!r){
    continue;
  }

  ## Get TID
  tid = tconx_extract_tid(reply:r);
  if(!tid)
  {
    continue;
  }

  ## Get Tree ID and Process ID from the response packet
  tid_high = tid / 256;
  tid_low  = tid % 256;
  uid_high = uid / 256;
  uid_low  = uid % 256;

  resp = FindFirst2(socket:soc1, uid:uid, tid:tid, pattern: dir + "\*");

  if (!resp){
    continue;
  }

  ## Try to read each file
  foreach file (resp)
  {
    ## Get the FID
    fid = OpenAndX(socket:soc1, uid:uid, tid:tid, file:file);

    if(!fid){
     continue;
    }

    fid_high = fid / 256;
    fid_low  = fid % 256;

    ## SMB Read AndX Request
    ## Try to read at a very high offset
    smb_read_andx_req = raw_string(0x00, 0x00, 0x00, 0x3c,           ## Netbios Session
                                   0xff, 0x53, 0x4d, 0x42,           ## Server Component : SMB
                                   0x2e,                             ## SMB Command : Read AndX
                                   0x00, 0x00, 0x00, 0x00,           ## NT Status : Success
                                   0x18, 0x07, 0xc8,                 ## Flags
                                   0x00, 0x00,                       ## Process ID
                                   0x01, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00,     ## Signature & Reserver
                                   tid_low, tid_high,                ## Tree ID
                                   0x33, 0x0c,
                                   uid_low, uid_high, 0x80, 0x01,    ## User ID
                                   0x0c,                             ## Read AndX Word Count
                                   0xff, 0x00,                       ## AndXCommand : No further cmds & Reserved
                                   0x00, 0x00,                       ## AndXoffset
                                   fid_low, fid_high,                ## FID
                                   0xff, 0xff, 0xff, 0xff,           ## Offset : Should be set to large value
                                   0x0a, 0x00, 0x0a, 0x00,           ## Max & Min Count
                                   0xff, 0xff, 0xff, 0xff,           ## File offset & File RW length
                                   0x0a,
                                   0x00, 0xff, 0xff, 0xff, 0x7f,     ##  High Offset
                                   0x00, 0x00, 0x00);                ##  Byte Count

    send(socket:soc1, data: smb_read_andx_req);
    read_resp = smb_recv(socket:soc1, length:4096);

    ## Close the SMB Read AndX req
    smb_close_request(soc:soc1, uid:uid, tid:tid, fid:fid);

    ## Check if SMB NT_STATUS is STATUS_INVALID_PARAMETER (0xc000000d)
    if(read_resp && ord(read_resp[9]) == 13 && ord(read_resp[10]) == 0
                 && ord(read_resp[11]) == 0 && ord(read_resp[12]) == 192)
    {
      security_hole(port);
      close(soc1);
      exit(0);
    }
  }
}

close(soc1);
