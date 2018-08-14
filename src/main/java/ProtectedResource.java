import org.json.simple.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;

public class ProtectedResource extends HttpServlet {
    String scope,method;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        method = (String)session.getAttribute("method");

        JSONObject result = new JSONObject();
        result.put("message","Hello World!");

        if(!"basic".equals(method)){
            scope = (String)session.getAttribute("scope");
            String[] scopes = scope.split(" ");
            if(Arrays.asList(scopes).contains("write")){
                result.put("privileges","read write");
            }
            else{
                result.put("privileges","read");
            }
        }

        response.setContentType("application/json");
        PrintWriter out = response.getWriter();

        out.print(result);
        out.flush();

    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException{
        doGet(request,response);
    }
}
