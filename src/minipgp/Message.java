/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package minipgp;

import java.io.ByteArrayOutputStream;
import java.io.File;
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
import javax.crypto.spec.IvParameterSpec;
import javax.xml.parsers.*;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 *
 * @author leonardo
 */
public class Message {

    private String sender;
    private String recipient;
    private byte[] message;
    private byte[] iv;
    private byte[] signedHash;
    private boolean isEncrypted = false;
    private boolean isCompressed = false;

    public Message() {
    }

    public Message(String sender, String recipient, String message) throws NoSuchAlgorithmException {
        setSender(sender);
        setRecipient(recipient);
        setMessage(message);
    }

    public final void setSender(String sender) {
        this.sender = sender;
    }

    public String getSender() {
        return sender;
    }

    public final void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    public String getRecipient() {
        return this.recipient;
    }

    public boolean isSigned() {
        return signedHash != null && signedHash.length > 0;
    }
    
    public boolean isCompressed(){
        return isCompressed;
    }
    
    public boolean isEncrypted(){
        return isEncrypted;
    }

    public final void setMessage(String message) throws NoSuchAlgorithmException {
        this.message = message.getBytes();
        this.isCompressed = false;
        this.isEncrypted = false;
        iv = null;
    }

    public String getMessage() {
        return new String(this.message);
    }

    public static Message readMessageFromXML(File messageFile) throws IOException, ParserConfigurationException, SAXException {
        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(messageFile);
        Element root = doc.getDocumentElement();

        Message m = new Message();
        Node senderNode = root.getElementsByTagName("sender").item(0);
        m.sender = senderNode.getTextContent();
        Node recNode = root.getElementsByTagName("recipient").item(0);
        m.recipient = recNode.getTextContent();
        Node msgNode = root.getElementsByTagName("MessageData").item(0);
        m.message = PGPMethods.decodeBASE64(msgNode.getTextContent());
        NamedNodeMap msgAttrb = msgNode.getAttributes();
        m.isEncrypted = msgAttrb.getNamedItem("encrypted").getNodeValue().equals("true");
        m.isCompressed = msgAttrb.getNamedItem("compressed").getNodeValue().equals("true");
        if(m.isEncrypted){
            m.iv = PGPMethods.decodeBASE64(root.getElementsByTagName("iv").item(0).getTextContent());
        }
        String signature = root.getElementsByTagName("signature").item(0).getTextContent();
        if (signature.length() > 0) {
            m.signedHash = PGPMethods.decodeBASE64(signature);
        }
        return m;
    }

    public void saveMessageToXML(File messageFile, String encryptionPassword, PrivateKey signature, boolean compress)
            throws ParserConfigurationException, IOException, Exception {
        // Aplicando opções de segurança e compressão
        applyOptions(encryptionPassword, signature, compress);

        // Preparando arquivo XML
        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.newDocument();

        // Criando elementos XML
        Element root = doc.createElement("Message");
        Element senderElm, recElm, msgElm, ivElm, signElm;
        senderElm = doc.createElement("sender");
        recElm = doc.createElement("recipient");
        msgElm = doc.createElement("MessageData");
        ivElm = doc.createElement("iv");
        signElm = doc.createElement("signature");

        // Definindo valores dos elementos
        senderElm.setTextContent(sender);
        recElm.setTextContent(recipient);
        msgElm.setTextContent(PGPMethods.encodeBASE64(message));
        msgElm.setAttribute("encrypted", isEncrypted ? "true" : "false");
        msgElm.setAttribute("compressed", isCompressed ? "true" : "false");
        ivElm.setTextContent(PGPMethods.encodeBASE64(iv));
        signElm.setTextContent(PGPMethods.encodeBASE64(signedHash));

        // Definindo estrutura dos elementos
        doc.appendChild(root);
        root.appendChild(senderElm);
        root.appendChild(recElm);
        root.appendChild(msgElm);
        root.appendChild(ivElm);
        root.appendChild(signElm);

        // Gravando arquivo
        messageFile.createNewFile();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(messageFile);
        TransformerFactory transFactory = TransformerFactory.newInstance();
        Transformer transformer = transFactory.newTransformer();
        transformer.transform(source, result);
    }

    public void applyOptions(String encryptionPassword, PrivateKey signature, boolean compress)
            throws Exception {
        if (signature != null) {
            addSignature(signature);
        }
        if (encryptionPassword != null) {
            encryptMessage(encryptionPassword);
        }
        if (compress) {
            compressMessage();
        }
    }

    // Método para cifrar a mensagem usando AES.
    public void encryptMessage(String password)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, Exception {
        if (message != null) {
            if (!isEncrypted) {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                MessageDigest algorithm = MessageDigest.getInstance("MD5");
                byte[] key = algorithm.digest(password.getBytes());
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
                message = cipher.doFinal(message);
                iv = cipher.getIV();
                isEncrypted = true;
            } else {
                throw new Exception("Mensagem já está cifrada!");
            }
        } else {
            throw new Exception("Não há mensagem para cifrar!");
        }
    }

    // Método de decifrar a mensagem cifrada com AES.
    public void decryptMessage(String password)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, Exception {
        if (message != null) {
            if (isEncrypted && iv != null) {
                if (!isCompressed) {
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    MessageDigest algorithm = MessageDigest.getInstance("MD5");
                    byte[] key = algorithm.digest(password.getBytes());
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
                    message = cipher.doFinal(message);
                } else {
                    throw new Exception("A mensagem deve ser descomprimida antes de decifrar!");
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
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                int n;
                while (!compressor.finished()) {
                    n = compressor.deflate(buffer);
                    stream.write(buffer, 0, n);
                }
                message = stream.toByteArray();
                isCompressed = true;
            } else {
                throw new Exception("A mensagem já está comprimida!");
            }
        } else {
            throw new Exception("Não há mensagem para comprimir!");
        }
    }

    // Método para assinar a mensagem
    public void addSignature(PrivateKey privateKey) throws Exception {
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
    public boolean verifySignature(PublicKey publicKey) throws Exception {
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
                byte[] buffer = new byte[100];
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                int n;
                while (!decompressor.finished()) {
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

}
