/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package minipgp;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;

/**
 *
 * @author leonardo
 */
public class PGPMethods {

    public static void generateKeyPair(String owner) throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        savePrivateKey(owner, kp.getPrivate());
        savePublicKey(owner, kp.getPublic());
    }

    public static void savePrivateKey(String owner, PrivateKey key)
            throws ParserConfigurationException, IOException, Exception {
        // Preparando arquivo XML
        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.newDocument();

        // Criando elementos XML
        Element root = doc.createElement("PrivateKey");
        Element ownerElm, keyElm;
        ownerElm = doc.createElement("owner");
        keyElm = doc.createElement("key");

        // Definindo valores dos elementos
        ownerElm.setTextContent(owner);
        keyElm.setTextContent(PGPMethods.encodeBASE64(key.getEncoded()));

        // Definindo estrutura dos elementos
        doc.appendChild(root);
        root.appendChild(ownerElm);
        root.appendChild(keyElm);

        // Gravando arquivo
        File keyFile = new File(Main.priKeyDir + owner + ".xml");
        keyFile.createNewFile();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(keyFile);
        TransformerFactory transFactory = TransformerFactory.newInstance();
        Transformer transformer = transFactory.newTransformer();
        transformer.transform(source, result);
    }

    public static void savePublicKey(String owner, PublicKey key)
            throws ParserConfigurationException, IOException, Exception {
        // Preparando arquivo XML
        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.newDocument();

        // Criando elementos XML
        Element root = doc.createElement("PublicKey");
        Element ownerElm, keyElm;
        ownerElm = doc.createElement("owner");
        keyElm = doc.createElement("key");

        // Definindo valores dos elementos
        ownerElm.setTextContent(owner);
        keyElm.setTextContent(PGPMethods.encodeBASE64(key.getEncoded()));

        // Definindo estrutura dos elementos
        doc.appendChild(root);
        root.appendChild(ownerElm);
        root.appendChild(keyElm);

        // Gravando arquivo
        File keyFile = new File(Main.pubKeyDir + owner + ".xml");
        keyFile.createNewFile();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(keyFile);
        TransformerFactory transFactory = TransformerFactory.newInstance();
        Transformer transformer = transFactory.newTransformer();
        transformer.transform(source, result);
    }

    public static PrivateKey getPrivateKey(String owner)
            throws IOException, ParserConfigurationException, SAXException, InvalidKeyException, Exception {
        File keyFile = new File(Main.priKeyDir + owner + ".xml");
        if (keyFile.exists()) {
            DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document doc = db.parse(keyFile);
            Element root = doc.getDocumentElement();

            if (root.getTagName().equals("PrivateKey")) {
                Node ownerNode = root.getElementsByTagName("owner").item(0);
                if (ownerNode.getTextContent().equals(owner)) {
                    Node keyNode = root.getElementsByTagName("key").item(0);
                    return RSAPrivateCrtKeyImpl.newKey(decodeBASE64(keyNode.getTextContent()));
                } else {
                    throw new Exception("Arquivo não corresponde ao usuário!");
                }
            } else {
                throw new Exception("Arquivo inválido!");
            }
        } else {
            throw new Exception("Não há chave privada armazenada para '" + owner + "'.");
        }
    }
    
    public static PublicKey getPublicKey(String owner)
            throws IOException, ParserConfigurationException, SAXException, InvalidKeyException, Exception {
        File keyFile = new File(Main.pubKeyDir + owner + ".xml");
        if (keyFile.exists()) {
            DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document doc = db.parse(keyFile);
            Element root = doc.getDocumentElement();

            if (root.getTagName().equals("PublicKey")) {
                Node ownerNode = root.getElementsByTagName("owner").item(0);
                if (ownerNode.getTextContent().equals(owner)) {
                    Node keyNode = root.getElementsByTagName("key").item(0);
                    return new RSAPublicKeyImpl(decodeBASE64(keyNode.getTextContent()));
                } else {
                    throw new Exception("Arquivo não corresponde ao usuário!");
                }
            } else {
                throw new Exception("Arquivo inválido!");
            }
        } else {
            throw new Exception("Não há chave publica armazenada para '" + owner + "'.");
        }
    }

    public static String encodeBASE64(byte[] data) throws Exception {
        if (data == null) {
            return null;
        }
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(data);
    }

    public static byte[] decodeBASE64(String dataString) throws IOException {
        if (dataString == null) {
            return null;
        }
        BASE64Decoder decoder = new BASE64Decoder();
        return decoder.decodeBuffer(dataString);
    }

    public static boolean matchBytes(byte[] data1, byte[] data2) {
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
