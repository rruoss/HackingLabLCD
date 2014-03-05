# Microsoft Developer Studio Generated NMAKE File, Based on mod_but.dsp
!IF "$(CFG)" == ""
CFG=mod_but - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_but - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_but - Win32 Release" && "$(CFG)" != "mod_but - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_but.mak" CFG="mod_but - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_but - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_but - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_but - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : ".\mod_but.rc" "$(OUTDIR)\mod_but.so"

!ELSE 

ALL : "libhttpd - Win32 Release" "libaprutil - Win32 Release" "libapr - Win32 Release" ".\mod_but.rc" "$(OUTDIR)\mod_but.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN" "libhttpd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_but.obj"
	-@erase "$(INTDIR)\mod_but_src.idb"
	-@erase "$(INTDIR)\mod_but_src.pdb"
	-@erase "$(INTDIR)\mod_but_access.obj"
	-@erase "$(INTDIR)\mod_but_authorization.obj"
	-@erase "$(INTDIR)\mod_but_config.obj"
	-@erase "$(INTDIR)\mod_but_cookiestore.obj"
	-@erase "$(INTDIR)\mod_but_output_filter.obj"
	-@erase "$(INTDIR)\mod_but_request_filter.obj"
	-@erase "$(INTDIR)\mod_but_session.obj"
	-@erase "$(INTDIR)\mod_but_shm.obj"
	-@erase "$(OUTDIR)\mod_but.exp"
	-@erase "$(OUTDIR)\mod_but.lib"
	-@erase "$(OUTDIR)\mod_but.pdb"
	-@erase "$(OUTDIR)\mod_but.so"
	-@erase ".\mod_but.rc"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/pcre" /I "../../srclib/openssl/inc32/openssl" /I "../../srclib/openssl/inc32" /I "../ssl" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "PROXY_DECLARE_EXPORT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_but_src" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_but.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib mswsock.lib ssleay32.lib libeay32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_but.pdb" /debug /machine:I386 /out:"$(OUTDIR)\mod_but.so" /implib:"$(OUTDIR)\mod_but.lib" /libpath:"../../srclib/openssl/out32dll" /libpath:"../../srclib/openssl/out32" /base:@..\..\os\win32\BaseAddr.ref,mod_but.so /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\mod_but.obj" \
	"$(INTDIR)\mod_but_access.obj" \
	"$(INTDIR)\mod_but_authorization.obj" \
	"$(INTDIR)\mod_but_config.obj" \
	"$(INTDIR)\mod_but_cookiestore.obj" \
	"$(INTDIR)\mod_but_output_filter.obj" \
	"$(INTDIR)\mod_but_request_filter.obj" \
	"$(INTDIR)\mod_but_session.obj" \
	"$(INTDIR)\mod_but_shm.obj" \
	"..\ssl\Release\mod_ssl.obj" \
	"..\ssl\Release\ssl_engine_config.obj" \
	"..\ssl\Release\ssl_engine_dh.obj" \
	"..\ssl\Release\ssl_engine_init.obj" \
	"..\ssl\Release\ssl_engine_io.obj" \
	"..\ssl\Release\ssl_engine_kernel.obj" \
	"..\ssl\Release\ssl_engine_log.obj" \
	"..\ssl\Release\ssl_engine_mutex.obj" \
	"..\ssl\Release\ssl_engine_pphrase.obj" \
	"..\ssl\Release\ssl_engine_rand.obj" \
	"..\ssl\Release\ssl_engine_vars.obj" \
	"..\ssl\Release\ssl_expr.obj" \
	"..\ssl\Release\ssl_expr_eval.obj" \
	"..\ssl\Release\ssl_expr_parse.obj" \
	"..\ssl\Release\ssl_expr_scan.obj" \
	"..\ssl\Release\ssl_scache.obj" \
	"..\ssl\Release\ssl_scache_dbm.obj" \
	"..\ssl\Release\ssl_scache_shmcb.obj" \
	"..\ssl\Release\ssl_scache_shmht.obj" \
	"..\ssl\Release\ssl_util.obj" \
	"..\ssl\Release\ssl_util_ssl.obj" \
	"..\ssl\Release\ssl_util_table.obj" \
	"..\..\srclib\apr\Release\libapr.lib" \
	"..\..\srclib\apr-util\Release\libaprutil.lib" \
	"..\..\Release\libhttpd.lib" \
	"..\..\srclib\pcre\LibR\pcre.lib" \
	"..\ssl\Release\mod_ssl.lib"

"$(OUTDIR)\mod_but.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_but - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : ".\mod_but.rc" "$(OUTDIR)\mod_but.so"

!ELSE 

ALL : "libhttpd - Win32 Debug" "libaprutil - Win32 Debug" "libapr - Win32 Debug" ".\mod_but.rc" "$(OUTDIR)\mod_but.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN" "libhttpd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_but.obj"
	-@erase "$(INTDIR)\mod_but_src.idb"
	-@erase "$(INTDIR)\mod_but_src.pdb"
	-@erase "$(INTDIR)\mod_but_access.obj"
	-@erase "$(INTDIR)\mod_but_authorization.obj"
	-@erase "$(INTDIR)\mod_but_config.obj"
	-@erase "$(INTDIR)\mod_but_cookiestore.obj"
	-@erase "$(INTDIR)\mod_but_output_filter.obj"
	-@erase "$(INTDIR)\mod_but_request_filter.obj"
	-@erase "$(INTDIR)\mod_but_session.obj"
	-@erase "$(INTDIR)\mod_but_shm.obj"
	-@erase "$(OUTDIR)\mod_but.exp"
	-@erase "$(OUTDIR)\mod_but.lib"
	-@erase "$(OUTDIR)\mod_but.pdb"
	-@erase "$(OUTDIR)\mod_but.so"
	-@erase ".\mod_but.rc"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "PROXY_DECLARE_EXPORT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_but_src" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_but.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib mswsock.lib ssleay32.lib libeay32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_but.pdb" /debug /machine:I386 /out:"$(OUTDIR)\mod_but.so" /implib:"$(OUTDIR)\mod_but.lib" /base:@..\..\os\win32\BaseAddr.ref,mod_but.so 
LINK32_OBJS= \
	"$(INTDIR)\mod_but.obj" \
	"$(INTDIR)\mod_but_access.obj" \
	"$(INTDIR)\mod_but_authorization.obj" \
	"$(INTDIR)\mod_but_config.obj" \
	"$(INTDIR)\mod_but_cookiestore.obj" \
	"$(INTDIR)\mod_but_output_filter.obj" \
	"$(INTDIR)\mod_but_request_filter.obj" \
	"$(INTDIR)\mod_but_session.obj" \
	"$(INTDIR)\mod_but_shm.obj" \
	"..\ssl\Release\mod_ssl.obj" \
	"..\ssl\Release\ssl_engine_config.obj" \
	"..\ssl\Release\ssl_engine_dh.obj" \
	"..\ssl\Release\ssl_engine_init.obj" \
	"..\ssl\Release\ssl_engine_io.obj" \
	"..\ssl\Release\ssl_engine_kernel.obj" \
	"..\ssl\Release\ssl_engine_log.obj" \
	"..\ssl\Release\ssl_engine_mutex.obj" \
	"..\ssl\Release\ssl_engine_pphrase.obj" \
	"..\ssl\Release\ssl_engine_rand.obj" \
	"..\ssl\Release\ssl_engine_vars.obj" \
	"..\ssl\Release\ssl_expr.obj" \
	"..\ssl\Release\ssl_expr_eval.obj" \
	"..\ssl\Release\ssl_expr_parse.obj" \
	"..\ssl\Release\ssl_expr_scan.obj" \
	"..\ssl\Release\ssl_scache.obj" \
	"..\ssl\Release\ssl_scache_dbm.obj" \
	"..\ssl\Release\ssl_scache_shmcb.obj" \
	"..\ssl\Release\ssl_scache_shmht.obj" \
	"..\ssl\Release\ssl_util.obj" \
	"..\ssl\Release\ssl_util_ssl.obj" \
	"..\ssl\Release\ssl_util_table.obj" \
	"..\..\srclib\apr\Debug\libapr.lib" \
	"..\..\srclib\apr-util\Debug\libaprutil.lib" \
	"..\..\Debug\libhttpd.lib" \
	"..\..\srclib\pcre\LibR\pcre.lib" \
	"..\ssl\Release\mod_ssl.lib"

"$(OUTDIR)\mod_but.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_but.dep")
!INCLUDE "mod_but.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_but.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_but - Win32 Release" || "$(CFG)" == "mod_but - Win32 Debug"
SOURCE=.\mod_but.c

"$(INTDIR)\mod_but.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\mod_but_access.c

"$(INTDIR)\mod_but_access.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\mod_but_authorization.c

"$(INTDIR)\mod_but_authorization.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\mod_but_config.c

"$(INTDIR)\mod_but_config.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\mod_but_cookiestore.c

"$(INTDIR)\mod_but_cookiestore.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\mod_but_output_filter.c

"$(INTDIR)\mod_but_output_filter.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\mod_but_request_filter.c

"$(INTDIR)\mod_but_request_filter.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\mod_but_session.c

"$(INTDIR)\mod_but_session.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\mod_but_shm.c

"$(INTDIR)\mod_but_shm.obj" : $(SOURCE) "$(INTDIR)"


!IF  "$(CFG)" == "mod_but - Win32 Release"

"libapr - Win32 Release" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\proxy"

"libapr - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\proxy"

!ELSEIF  "$(CFG)" == "mod_but - Win32 Debug"

"libapr - Win32 Debug" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\proxy"

"libapr - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\proxy"

!ENDIF 

!IF  "$(CFG)" == "mod_but - Win32 Release"

"libaprutil - Win32 Release" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" 
   cd "..\..\modules\proxy"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\proxy"

!ELSEIF  "$(CFG)" == "mod_but - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\proxy"

"libaprutil - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\proxy"

!ENDIF 

!IF  "$(CFG)" == "mod_but - Win32 Release"

"libhttpd - Win32 Release" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\proxy"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" RECURSE=1 CLEAN 
   cd ".\modules\proxy"

!ELSEIF  "$(CFG)" == "mod_but - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\proxy"

"libhttpd - Win32 DebugCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\modules\proxy"

!ENDIF 

SOURCE=..\..\build\win32\win32ver.awk

!IF  "$(CFG)" == "mod_but - Win32 Release"

InputPath=..\..\build\win32\win32ver.awk

".\mod_but.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	awk -f ../../build/win32/win32ver.awk mod_but.so "but_module for Apache" ../../include/ap_release.h > .\mod_but.rc
<< 
	

!ELSEIF  "$(CFG)" == "mod_but - Win32 Debug"

InputPath=..\..\build\win32\win32ver.awk

".\mod_but.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	<<tempfile.bat 
	@echo off 
	awk -f ../../build/win32/win32ver.awk mod_but.so "but_module for Apache" ../../include/ap_release.h > .\mod_but.rc
<< 
	

!ENDIF 


!ENDIF 

