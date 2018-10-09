import org.json.simple.JSONObject;
//import org.json.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.Base64;


public class ResourceFilter implements Filter {


    FilterConfig fConfig = null;
    String client_id;
    String refreshToken;
    String client_secret;
    Object obj;

    public void init(FilterConfig config) throws ServletException {
        fConfig = config;
    }

    public void doFilter(ServletRequest req, ServletResponse resp,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse)resp;

        String authString = (String)request.getHeader("Authorization");
        String provider = request.getHeader("Provider");
        if(authString != null && !authString.isEmpty()){
            String[] params = authString.split(" ");

            HttpSession session = request.getSession();

            if("Bearer".equals(params[0]) && !provider.equals("WSO2")){
                String access_Token = params[1];
                byte[] ba = Base64.getDecoder().decode(access_Token.split("\\.")[1]);

                String decoded = new String(ba);

                JSONParser parser = new JSONParser();

                try {
                    obj = parser.parse(decoded);

                } catch (ParseException e) {
                    System.out.println(e);
                }

                JSONObject jsonObj = (JSONObject) obj;
                long epoch = System.currentTimeMillis()/1000;
                long iat = (Long)jsonObj.get("iat");
                long exp = (Long)jsonObj.get("exp");

                boolean active = ((iat < epoch) && (exp >epoch));

                String scope = (String)jsonObj.get("scope");
                session.setAttribute("scope",scope);
                System.out.println("Scopes: " + scope);
                String[] scopes = scope.split(" ");

                if((active) && Arrays.asList(scopes).contains("read")) {
                    chain.doFilter(request, response);
                }
                else{
                    response.setContentType("application/json");
                    response.setStatus(401);
                }

                //build url

            }
            else if("Bearer".equals(params[0]) && provider.equals("WSO2")){
                String access_Token = params[1];
                QueryBuilder codeBuilder = new QueryBuilder();
                codeBuilder.append("token", access_Token);

//                String EndPoint = " https://localhost:9443/oauth2/introspect";
                String EndPoint = "https://localhost:9443/oauth2/introspect";
                String url = EndPoint + "?";
//                String credentials = (String)request.getHeader("ClientCredentials");
                codeBuilder.append("token", access_Token);
                String body = codeBuilder.returnQuery("");


                URL object = new URL(url);
                HttpURLConnection con = (HttpURLConnection) object.openConnection();

                con.setRequestMethod("POST");

                //add request header
                con.setRequestProperty("Content-type", "application/x-www-form-urlencoded");
                con.setRequestProperty("Authorization", "Bearer " + access_Token);
//                con.setRequestProperty("Authorization", "Basic " + credentials);

                con.setDoOutput(true);
                DataOutputStream wr = new DataOutputStream(con.getOutputStream());
                wr.writeBytes(body);
                wr.flush();
                wr.close();


                try{
                    BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));

                    String inputLine;
                    StringBuffer re = new StringBuffer();
                    while ((inputLine = in.readLine()) != null) {
                        re.append(inputLine);
                    }
                    in.close();

                    //Read JSON response
                    org.json.JSONObject myResponse = new org.json.JSONObject(re.toString());
                    System.out.println(myResponse);


                    String active = String.valueOf(myResponse.getBoolean("active"));
                    String scope = (String)myResponse.get("scope");
                    session.setAttribute("scope",scope);
                    String[] scopes = scope.split(" ");
//                    String client = (String)myResponse.get("client_id");
//
//                    String client_id = (String)session.getAttribute("client_id");

                    if("true".equals(active) && Arrays.asList(scopes).contains("read")){
                        chain.doFilter(request,response);
                    }
                    else{
                        response.setContentType("application/json");
                        response.setStatus(401);
                    }

                }
                catch (IOException e){
                    System.out.println(e);
                    if (session != null) {
                        session.invalidate();
                    }

//                    if(!((session.getAttribute("refresh_token"))==null)) {
//                        session.setAttribute("grant_type", "refresh_token");
//                        response.sendRedirect("JSON");
//                    }else{
//                        response.sendRedirect("home?errorMessage=Access Token Invalid");
//                    }

                }
            }
            else{
                String base64Credentials = authString.substring("Basic".length()).trim();
                String credentials = new String(Base64.getDecoder().decode(base64Credentials),
                        Charset.forName("UTF-8"));
                // credentials = username:password
                final String[] values = credentials.split(":",2);
//                String credString = params[1];
//                String[] creds = credString.split(":");


//                String username = fConfig.getInitParameter("username");
//                String password = fConfig.getInitParameter("password");
                try{
                    Class.forName("oracle.jdbc.driver.OracleDriver");

                    Connection con = null;

                    con = DriverManager.getConnection("jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=cmbpde2293)(PORT=1521)))(CONNECT_DATA=(SERVICE_NAME=s2293)))",values[0],values[1]);

                    if(con != null){
                        session.setAttribute("method","basic");
                        chain.doFilter(request, response);
                    }
                    else{
                        response.setContentType("application/json");
                        response.setStatus(401);
                    }
                }
                catch (Exception e){
                    response.setContentType("application/json");
                    response.setStatus(401);

                }
            }
        }
        else{
            response.setContentType("application/json");
            response.setStatus(401);
        }

    }
//Arrays.asList(scope.split(" ")).contains("openid")
    
    public void destroy() {}


}