import java.security.MessageDigest;
import java.util.Base64;  
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
class Main {
  static MessageDigest md;
  static String Secret="SECRET";
  static Base64.Encoder encoder = Base64.getEncoder();  
  public static void main(String[] args) throws NoSuchAlgorithmException{
    System.out.println("Hello world!");
    md=MessageDigest.getInstance("SHA-256"); 
  System.out.println(generateToken());
  ValidateToken(generateToken());
  }
  
  public static String generateToken()
  {
    String username="Himanshu";
    String queryparams="cen";
    byte[] encodedusername=encoder.encode(username.getBytes());
    byte[] encodedparams=encoder.encode(queryparams.getBytes());
    byte[] combinedarray=new byte[encodedusername.length+encodedparams.length];
    System.arraycopy(encodedusername, 0, combinedarray, 0, encodedusername.length);
     System.arraycopy(encodedparams, 0, combinedarray, encodedusername.length, encodedparams.length);
    
    md.update(combinedarray);
    byte[] signature=md.digest(Secret.getBytes());


    final String token=new String(encodedusername)+'.'+new String(encodedparams)+'.'+new String(signature);
    
    return token;
     
  }
  public static void ValidateToken(String token)
  {
    String[] tokeninfo = token.split("\\.");
    
    byte[] username=tokeninfo[0].getBytes();
    byte[] params=tokeninfo[1].getBytes();
    byte[] combinedarray=new byte[username.length+params.length];
    System.arraycopy(username, 0, combinedarray, 0, username.length);
     System.arraycopy(params, 0, combinedarray, username.length, params.length);
    
    md.update(combinedarray);
    byte[] signature=md.digest(Secret.getBytes());
    final String tokentocheck=new String(username)+'.'+new String(params)+'.'+new String(signature);
    System.out.println(tokentocheck);
    if(generateToken().equals(tokentocheck))
    {
      System.out.print("User Validated");
    }
    else
       System.out.print("Nope");
  }

}