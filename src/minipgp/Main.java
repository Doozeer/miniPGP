/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package minipgp;

import java.io.File;

/**
 *
 * @author leonardo
 */
public class Main {
    
    public static final String msgDir = "Messages/";
    public static final String pubKeyDir = "Public Keys/";
    public static final String priKeyDir = "Private Keys/";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        // Criar diretórios do programa, caso não existam
        File m, pubK, priK;
        m = new File(msgDir);
        pubK = new File(pubKeyDir);
        priK = new File(priKeyDir);
        if(!m.exists()){
            m.mkdir();
        }
        if(!pubK.exists()){
            pubK.mkdir();
        }
        if(!priK.exists()){
            priK.mkdir();
        }
        
        Message msg = new Message("dozeer@gmail.com", "leonardo.filipe@live.com", "top kek lol\nfagt.");
        File f = new File("Messages/test.xml");
        PGPMethods.generateKeyPair("dozeer@gmail.com");
        msg.saveMessageToXML(f, "stormageddon123", PGPMethods.getPrivateKey("dozeer@gmail.com"), true);
        Message file = Message.readMessageFromXML(f);
        file.decompressMessage();
        file.decryptMessage("stormageddon123");
        System.out.println(file.verifySignature(PGPMethods.getPublicKey(file.getSender())));
        System.out.println(file.getMessage());
    }
    
}
