package acertum.secureRequestHandler.entities;

public class RequestResponse {
    public enum RESPONSE_CODE{
        SUCCESS,
        ERROR
    }
    private RESPONSE_CODE code;
    private String result;
    
    public RequestResponse(RESPONSE_CODE code, String result){
        this.code = code;
        this.result = result;
    }

    public RESPONSE_CODE getCode() {
        return code;
    }

    public void setCode(RESPONSE_CODE code) {
        this.code = code;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }
}
