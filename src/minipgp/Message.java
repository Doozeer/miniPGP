/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package minipgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 *
 * @author leonardo
 */
public class Message {

    private String sender;
    private String recipient;
    private byte[] message;
    private byte[] messageHash;
    private byte[] signedHash;
    private boolean isEncrypted = false;
    private boolean isCompressed = false;

    // Método para cifrar a mensagem usando AES.
    public void encryptMessage(byte[] password)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, Exception {
        if (message != null) {
            if (!isEncrypted) {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                MessageDigest algorithm = MessageDigest.getInstance("SHA-256");
                byte[] key = algorithm.digest(password);
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
                messageHash = algorithm.digest(message);
                message = cipher.doFinal(message);
                isEncrypted = true;
            } else {
                throw new Exception("Mensagem já está cifrada!");
            }
        } else {
            throw new Exception("Não há mensagem para cifrar!");
        }
    }

    // Método de decifrar a mensagem cifrada com AES.
    public void decryptMessage(byte[] password)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, Exception {
        if (message != null) {
            if (isEncrypted) {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                MessageDigest algorithm = MessageDigest.getInstance("SHA-256");
                byte[] key = algorithm.digest(password);
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
                byte[] temp = cipher.doFinal(message);
                if (matchBytes(algorithm.digest(temp), messageHash)) {
                    isEncrypted = false;
                    message = temp;
                } else {
                    throw new Exception("Senha inválida!");
                }
            } else {
                throw new Exception("Mensagem não está cifrada!");
            }
        } else {
            throw new Exception("Não há mensagem para decifrar!");
        }
    }

    // Método de compressão ZIP da mensagem.
    public void compressMessage() throws Exception {
        if (message != null) {
            if (!isCompressed) {
                Deflater compressor = new Deflater();
                compressor.setInput(message);
                compressor.finish();
                byte[] buffer = new byte[message.length];
                int compressedLength = compressor.deflate(buffer);
                message = new byte[compressedLength];
                System.arraycopy(buffer, 0, message, 0, compressedLength);
                isCompressed = true;
            } else {
                throw new Exception("A mensagem já está comprimida!");
            }
        } else {
            throw new Exception("Não há mensagem para comprimir!");
        }
    }
    
    // Método para assinar a mensagem
    public void addSignature(PrivateKey privateKey) throws Exception{
        if (message != null) {
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(privateKey);
            sign.update(message);
            signedHash = sign.sign();
        } else {
            throw new Exception("Não há mensagem para assinar!");
        }
    }
    
    // Método para verificar assinatura de mensagem.
    public boolean verifySignature(PublicKey publicKey) throws Exception{
        if (message != null && signedHash != null) {
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(publicKey);
            sign.update(message);
            return sign.verify(signedHash);
        } else {
            throw new Exception("Não há mensagem ou assinatura para verificar!");
        }
    }
    
    // Método de descompressão ZIP da mensagem.
    public void decompressMessage() throws Exception {
        if (message != null) {
            if (isCompressed) {
                Inflater decompressor = new Inflater();
                decompressor.setInput(message);
                byte[] buffer = new byte[1000];
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                int n;
                while(!decompressor.finished()){
                    n = decompressor.inflate(buffer);
                    stream.write(buffer, 0, n);
                }
                message = stream.toByteArray();
                isCompressed = false;
            } else {
                throw new Exception("A mensagem não está comprimida!");
            }
        } else {
            throw new Exception("Não há mensagem para descomprimir!");
        }
    }
    
    public String getBASE64Message() throws Exception {
        if(message != null) {
            BASE64Encoder encoder = new BASE64Encoder();
            return encoder.encode(message);
        } else {
            throw new Exception("Não há mensagem para codificar!");
        }
    }
    
    public void setMessageFromBASE64(String BASE64message) throws IOException{
        BASE64Decoder decoder = new BASE64Decoder();
        message = decoder.decodeBuffer(BASE64message);
    }

    private static boolean matchBytes(byte[] data1, byte[] data2) {
        int len = data1.length;
        if (len != data2.length) {
            return false;
        }

        boolean b = true;
        for (int i = 0; i < len && b; i++) {
            b &= data1[i] == data2[i];
        }
        return b;
    }
}
