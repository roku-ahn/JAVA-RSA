package hellTest;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;


import java.math.BigInteger;
public class hellowJava {

	public  static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
	{
		System.out.println("Hello");
		
    
		HashMap<String, Object> keys = new HashMap<String, Object>();
	    
	    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        
        KeyPair keyPair = generator.genKeyPair();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        String stringPrivateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        //HttpSession session = request.getSession();
        //session.setAttribute("__rsaPrivateKey__", privateKey);
        
        System.out.println("privateKey:" + privateKey.toString());  
        System.out.println("stringPrivateKey:" + stringPrivateKey);  
        System.out.println("publicKey:" + publicKey.toString());

        // 공개키를 문자열로 변환하여 JavaScript RSA 라이브러리 넘겨준다.
        RSAPublicKeySpec publicSpec = (RSAPublicKeySpec) keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);

        String publicKeyModulus = publicSpec.getModulus().toString(16);
        String publicKeyExponent = publicSpec.getPublicExponent().toString(16);
        Encoder b64e = Base64.getEncoder();

      byte[] by = publicSpec.getModulus().toByteArray();
        keys.put("publicKeyModulus", publicKeyModulus);
        keys.put("publicKeyExponent", publicKeyExponent);       
        System.out.println("publicKeyModulus:" + publicSpec.getModulus().toString());
       // System.out.println("publicKeyModulus:" + publicKeyModulus);
        by.toString();
        System.out.println("publicKeyExponent:" + publicSpec.getPublicExponent().toString());
        //System.out.println("publicKeyExponent:" + publicKeyExponent);
        //암호해독
        
      String stringPrivateKey2 = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAId+COuhtZTk9DO8uV3HyEivK//y2ojefhuty3+GA/CZjp4f7U9jVaRltR26bRNThtmauK1Ol/wqUIV3f4p3Vn5baHl+RqH+0/+A4Hhmp7KaAM5HGybQoaY/xkI0Y3NsZQGwVYiFmEgwF0Te13iNddDsXxsnY3DdOSFsz4mMr6qNAgMBAAECgYBoep+WU5QZxJMqchTeY/flVG6xZyts72R/I30QUN8o4MBA3o238flQU71dtyv1AyuxEMXnnftEz7xXrtYCiBOBK8W3qlb5O+W+81i3r/o4y1V2ifk6SmoDDG4ISYAtUbXSt8LvkEw6WCWD26EThmDTTEgP8WaVhT8GmOi1Mdz2YQJBAMvQAPga5FvNNgG864vbWNXqOnxveLqIhracgwoV6uuZkhcLNsrRG9QLnbd2/OnMcxH1QlPgXNevJsoSVfQsCXsCQQCqL50eT4wZnAdAh08Mt1BgXRUSMw3pLIw7tpb3XCDeos6P+zd+QQ+Qch8vS3641Zyutbre03yEhegyZ91DZkmXAkBvi5u8LhulEp7oPJk9pgLssJDp4ahVjrsL3oTpVC2KXDZUXlLSlbeBSgo7iufInZisz2pJtZWahcXY+kgIpsFZAkEAgZEkdporWKgAoXEijtTVfbgAPc3ezmJbFW8quoJKiBW9W8Lv+dBAsEEiWtiITuJammzDK7gpeZ+VKyMGQrUSWwJBAIego5v1kJBg9kiBIHuH8d+ZQx1ysBjI3bOxiHdO3CHBs65NB2WOhqNK6/Gz51VsndVpSBU+6DmzrTj4MGWVjuY=";
      //String stringPrivateKey3 = "6B9C6DF2CF486266A5A6FDA0876F852F";
     
      
      //String str = "LDQoMJw92sbhsAvuQSetXKBYhhIc2HrWVkZcLB71XAXbaxg/llQks4hAVVigiRDveoNI1QScbHDcti5GVUBXfeLvRWdYGFjJcw7aTtwvbIWNRUApcIiJZ75DcBApTu+UnykOQuWBsIuF9QR8izDjjr78kqoxcXXhWL0ZruL54zU=";
      //byte[] bystr =str.getBytes();
      //LBI+CbfjEazUln1dtEpUG2LCIN3Qc6I+sJzM6ofuMqzb4n4jnHSthHvMaste4Dbrh3HxahrYvI+leJELQUsSgMW85mDkV6LTE2TC7MjXhL6TrJeGnaO+GwIOrCrH66fWI+rqa3ld/Y069Edmj3w0TVGoKA0EKeJCL7T/NLt6KYw=
      String str ="2C3428309C3DDAC6E1B00BEE4127AD5CA05886121CD87AD656465C2C1EF55C05DB6B183F965424B388405558A08910EF7A8348D5049C6C70DCB62E465540577DE2EF4567581858C9730EDA4EDC2F6C858D45402970888967BE437010294EEF949F290E42E581B08B85F5047C8B30E38EBEFC92AA317175E158BD19AEE2F9E335";
      //String str = "89636faf967f1d8607b4d0f34166002a7658e4640a6102f93ee0684511823d5b530e63d15b41fe9864ecacc396e0bec3d48f88b57d3dda847dda85a4561996e62df2673b2a2708ffa24c4647c5d0eead7a1bb1c3b2811aa0e67d0c733726c7fc3f1fe0b73e2ea415c61d4c8b9ef6f23090a310d5fa6260ab28e8f493d15c1fe7";
      byte[] bystr = hexStringToByteArray(str);
      String hexstr = byteArrayToHexString(bystr);

      System.out.println(str);
      System.out.println(hexstr);
        final int RADIX = 16;

      //평문으로 전달받은 개인키를 개인키객체로 만드는 과정
        KeyFactory keyFactory2 = KeyFactory.getInstance("RSA");
        byte[] bytePrivateKey = Base64.getDecoder().decode(stringPrivateKey2.getBytes());
        //byte[] bytePrivateKey = hexStringToByteArray(stringPrivateKey3);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
        PrivateKey privateKey2 = keyFactory2.generatePrivate(privateKeySpec);
        
        
        //만들어진 공개키객체를 기반으로 암호화모드로 설정하는 과정
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey2);
        

      //암호문을 평문화하는 과정
        //byte[] byteEncryptedData = Base64.getDecoder().decode(bystr);        
        byte[]  byteEncryptedData = hexToByteArray(str);
        byte[] byteDecryptedData = cipher.doFinal(byteEncryptedData);        
        //byte[] byteDecryptedData = cipher.doFinal(encrypted);
        String decryptedData = new String(byteDecryptedData, "utf-8");

        //byte[] byteEncryptedData = Base64.getDecoder().decode(s1.getBytes());
        //byte[] byteDecryptedData = cipher.doFinal(encrypted);
        //String decryptedData = new String(byteDecryptedData);

        
        System.out.println(decryptedData);
        
	}
	public static byte[] hexToByteArray(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            return new byte[]{};
        }

        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            byte value = (byte)Integer.parseInt(hex.substring(i, i + 2), 16);
            bytes[(int) Math.floor(i / 2)] = value;
        }
        return bytes;
    }
	
	public static byte[] hexStringToByteArray(String hex) {
	    int l = hex.length();
	    byte[] data = new byte[l / 2];
	    for (int i = 0; i < l; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
	                + Character.digit(hex.charAt(i + 1), 16));
	    }
	    return data;
	}

	public static String byteArrayToHexString(byte[] bytes){ 
		
		StringBuilder sb = new StringBuilder(); 
		
		for(byte b : bytes){ 
			
			sb.append(String.format("%02X", b&0xff)); 
		} 
		
		return sb.toString(); 
	} 
}
