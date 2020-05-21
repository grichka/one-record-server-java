package com.wisekey.openidconnect;

import java.util.List;

public class ResponseJwks {
    private List<ResponseJwksItem> keys;
	private String raw;
	
	public List<ResponseJwksItem> getKeys() {
		return this.keys;
	}
	
	public String getRaw() {
		return this.raw;
	}
	
	public void setRaw(String raw) {
		this.raw = raw;
	}
	
	public ResponseJwksItem getLastKey() {
		if (this.keys == null) return null;
		if (this.keys.isEmpty()) return null;
		int lastIndex = this.keys.size();
		return this.keys.get(lastIndex - 1);
	}    
}