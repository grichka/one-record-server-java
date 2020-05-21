package com.wisekey.openidconnect;

import com.google.gson.Gson;

public class ResponseTokenInfo {
    private String id_token;
    private String access_token;
    private int expires_in;
    private String token_type;
    private String raw;
    
    public ResponseTokenInfo() {
    	 
    }
 
    public static ResponseTokenInfo FromJson(String jsonString) {
    	
    	if (jsonString == null || "".equals(jsonString)) return null;
    	try {
    		Gson converter = new Gson();
    		ResponseTokenInfo data = converter.fromJson(jsonString, ResponseTokenInfo.class);
    		
    		if (data != null) data.raw = jsonString;
    		return data;
    		
		} catch (Exception e) {
			return null;
		}
    }
 
    public String getIdToken() {
        return id_token;
    }
 
    public void setIdToken(String idToken) {
        this.id_token = idToken;
    }

    public String getAccessToken() {
        return access_token;
    }
 
    public void setAccessToken(String accessToken) {
        this.access_token = accessToken;
    }
    
    public int getExpiresIn() {
        return expires_in;
    }
    
    public String getTokenType() {
        return token_type;
    }
    
    public String getRaw() {
        return raw;
    }
    
    public void setRaw(String raw) {
        this.raw = raw;
    }    
}