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
    String username="Himanshu"; //taking username or userid from request
    String queryparams="cen"; //taking some query params


    //encoding the username,queryparams and combining them.
    byte[] encodedusername=encoder.encode(username.getBytes());
    byte[] encodedparams=encoder.encode(queryparams.getBytes());
    byte[] combinedarray=new byte[encodedusername.length+encodedparams.length];
    System.arraycopy(encodedusername, 0, combinedarray, 0, encodedusername.length);
     System.arraycopy(encodedparams, 0, combinedarray, encodedusername.length, encodedparams.length);
    
    //adding Secret as a salt for computation 
    md.update(Secret.getBytes());

    //generating signature
    byte[] signature=md.digest(combinedarray);

    //generating the token
    final String token=new String(encodedusername)+'.'+new String(encodedparams)+'.'+new String(signature);
    
    //returning the token
    return token;
     
  }
  public static void ValidateToken(String token)
  {
    
    //getting the token from request
    String[] tokeninfo = token.split("\\.");
    

    //converting the username an params from token into bytearray
    byte[] username=tokeninfo[0].getBytes();
    byte[] params=tokeninfo[1].getBytes();
    byte[] combinedarray=new byte[username.length+params.length];
    System.arraycopy(username, 0, combinedarray, 0, username.length);
     System.arraycopy(params, 0, combinedarray, username.length, params.length);
    

    //adding the salt for computation
    md.update(Secret.getBytes());

    //generating the signature
    byte[] signature=md.digest(combinedarray);

    //getting the final token
    final String tokentocheck=new String(username)+'.'+new String(params)+'.'+new String(signature);
    System.out.println(tokentocheck);

    //checking for validation
    if(generateToken().equals(tokentocheck))
    {
      System.out.print("User Validated");
    }
    else
       System.out.print("Nope");
  }

}
