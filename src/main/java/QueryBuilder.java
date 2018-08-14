
import java.net.URLEncoder;
import java.io.UnsupportedEncodingException;

public class QueryBuilder {
    private String query = "";

    public void append(String name, String value){
        query += "&";
        encode(name, value);
    }

    public void encode(String name, String value){
        try{
            query += URLEncoder.encode(name, "UTF-8");
            query += "=";
            query += URLEncoder.encode(value, "UTF-8");

        }catch (UnsupportedEncodingException e){

        }
    }

    public String returnQuery(String endpointUri){
        return endpointUri + "?" + query;
    }
}
